package home

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/arpdb"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/stringutil"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// DHCP is an interface for accessing DHCP lease data the [clientsContainer]
// needs.
type DHCP interface {
	// Leases returns all the DHCP leases.
	Leases() (leases []*dhcpsvc.Lease)

	// HostByIP returns the hostname of the DHCP client with the given IP
	// address.  The address will be netip.Addr{} if there is no such client,
	// due to an assumption that a DHCP client must always have a hostname.
	HostByIP(ip netip.Addr) (host string)

	// MACByIP returns the MAC address for the given IP address leased.  It
	// returns nil if there is no such client, due to an assumption that a DHCP
	// client must always have a MAC address.
	MACByIP(ip netip.Addr) (mac net.HardwareAddr)
}

// clientsContainer is the storage of all runtime and persistent clients.
type clientsContainer struct {
	// TODO(a.garipov): Perhaps use a number of separate indices for different
	// types (string, netip.Addr, and so on).
	list    map[string]*Client // name -> client
	idIndex map[string]*Client // ID -> client

	// ipToRC maps IP addresses to runtime client information.
	ipToRC map[netip.Addr]*client.Runtime

	allTags *stringutil.Set

	// dhcp is the DHCP service implementation.
	dhcp DHCP

	// dnsServer is used for checking clients IP status access list status
	dnsServer *dnsforward.Server

	// etcHosts contains list of rewrite rules taken from the operating system's
	// hosts database.
	etcHosts *aghnet.HostsContainer

	// arpDB stores the neighbors retrieved from ARP.
	arpDB arpdb.Interface

	// lock protects all fields.
	//
	// TODO(a.garipov): Use a pointer and describe which fields are protected in
	// more detail.  Use sync.RWMutex.
	lock sync.Mutex

	// safeSearchCacheSize is the size of the safe search cache to use for
	// persistent clients.
	safeSearchCacheSize uint

	// safeSearchCacheTTL is the TTL of the safe search cache to use for
	// persistent clients.
	safeSearchCacheTTL time.Duration

	// testing is a flag that disables some features for internal tests.
	//
	// TODO(a.garipov): Awful.  Remove.
	testing bool
}

// Init initializes clients container
// dhcpServer: optional
// Note: this function must be called only once
func (clients *clientsContainer) Init(
	objects []*clientObject,
	dhcpServer DHCP,
	etcHosts *aghnet.HostsContainer,
	arpDB arpdb.Interface,
	filteringConf *filtering.Config,
) (err error) {
	if clients.list != nil {
		log.Fatal("clients.list != nil")
	}

	clients.list = map[string]*Client{}
	clients.idIndex = map[string]*Client{}
	clients.ipToRC = map[netip.Addr]*client.Runtime{}

	clients.allTags = stringutil.NewSet(clientTags...)

	// TODO(e.burkov):  Use [dhcpsvc] implementation when it's ready.
	clients.dhcp = dhcpServer

	clients.etcHosts = etcHosts
	clients.arpDB = arpDB
	err = clients.addFromConfig(objects, filteringConf)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	clients.safeSearchCacheSize = filteringConf.SafeSearchCacheSize
	clients.safeSearchCacheTTL = time.Minute * time.Duration(filteringConf.CacheTime)

	if clients.testing {
		return nil
	}

	// The clients.etcHosts may be nil even if config.Clients.Sources.HostsFile
	// is true, because of the deprecated option --no-etc-hosts.
	//
	// TODO(e.burkov):  The option should probably be returned, since hosts file
	// currently used not only for clients' information enrichment, but also in
	// the filtering module and upstream addresses resolution.
	if config.Clients.Sources.HostsFile && clients.etcHosts != nil {
		go clients.handleHostsUpdates()
	}

	return nil
}

// handleHostsUpdates receives the updates from the hosts container and adds
// them to the clients container.  It's used to be called in a separate
// goroutine.
func (clients *clientsContainer) handleHostsUpdates() {
	for upd := range clients.etcHosts.Upd() {
		clients.addFromHostsFile(upd)
	}
}

// webHandlersRegistered prevents a [clientsContainer] from registering its web
// handlers more than once.
//
// TODO(a.garipov): Refactor HTTP handler registration logic.
var webHandlersRegistered = false

// Start starts the clients container.
func (clients *clientsContainer) Start() {
	if clients.testing {
		return
	}

	if !webHandlersRegistered {
		webHandlersRegistered = true
		clients.registerWebHandlers()
	}

	go clients.periodicUpdate()
}

// reloadARP reloads runtime clients from ARP, if configured.
func (clients *clientsContainer) reloadARP() {
	if clients.arpDB != nil {
		clients.addFromSystemARP()
	}
}

// clientObject is the YAML representation of a persistent client.
type clientObject struct {
	SafeSearchConf filtering.SafeSearchConfig `yaml:"safe_search"`

	// BlockedServices is the configuration of blocked services of a client.
	BlockedServices *filtering.BlockedServices `yaml:"blocked_services"`

	Name string `yaml:"name"`

	IDs       []string `yaml:"ids"`
	Tags      []string `yaml:"tags"`
	Upstreams []string `yaml:"upstreams"`

	// UpstreamsCacheSize is the DNS cache size (in bytes).
	//
	// TODO(d.kolyshev): Use [datasize.Bytesize].
	UpstreamsCacheSize uint32 `yaml:"upstreams_cache_size"`

	// UpstreamsCacheEnabled indicates if the DNS cache is enabled.
	UpstreamsCacheEnabled bool `yaml:"upstreams_cache_enabled"`

	UseGlobalSettings        bool `yaml:"use_global_settings"`
	FilteringEnabled         bool `yaml:"filtering_enabled"`
	ParentalEnabled          bool `yaml:"parental_enabled"`
	SafeBrowsingEnabled      bool `yaml:"safebrowsing_enabled"`
	UseGlobalBlockedServices bool `yaml:"use_global_blocked_services"`

	IgnoreQueryLog   bool `yaml:"ignore_querylog"`
	IgnoreStatistics bool `yaml:"ignore_statistics"`
}

// addFromConfig initializes the clients container with objects from the
// configuration file.
func (clients *clientsContainer) addFromConfig(
	objects []*clientObject,
	filteringConf *filtering.Config,
) (err error) {
	for _, o := range objects {
		cli := &Client{
			Name: o.Name,

			IDs:       o.IDs,
			Upstreams: o.Upstreams,

			UseOwnSettings:        !o.UseGlobalSettings,
			FilteringEnabled:      o.FilteringEnabled,
			ParentalEnabled:       o.ParentalEnabled,
			safeSearchConf:        o.SafeSearchConf,
			SafeBrowsingEnabled:   o.SafeBrowsingEnabled,
			UseOwnBlockedServices: !o.UseGlobalBlockedServices,
			IgnoreQueryLog:        o.IgnoreQueryLog,
			IgnoreStatistics:      o.IgnoreStatistics,
			UpstreamsCacheEnabled: o.UpstreamsCacheEnabled,
			UpstreamsCacheSize:    o.UpstreamsCacheSize,
		}

		if o.SafeSearchConf.Enabled {
			o.SafeSearchConf.CustomResolver = safeSearchResolver{}

			err = cli.setSafeSearch(
				o.SafeSearchConf,
				filteringConf.SafeSearchCacheSize,
				time.Minute*time.Duration(filteringConf.CacheTime),
			)
			if err != nil {
				log.Error("clients: init client safesearch %q: %s", cli.Name, err)

				continue
			}
		}

		err = o.BlockedServices.Validate()
		if err != nil {
			return fmt.Errorf("clients: init client blocked services %q: %w", cli.Name, err)
		}

		cli.BlockedServices = o.BlockedServices.Clone()

		for _, t := range o.Tags {
			if clients.allTags.Has(t) {
				cli.Tags = append(cli.Tags, t)
			} else {
				log.Info("clients: skipping unknown tag %q", t)
			}
		}

		slices.Sort(cli.Tags)

		_, err = clients.Add(cli)
		if err != nil {
			log.Error("clients: adding clients %s: %s", cli.Name, err)
		}
	}

	return nil
}

// forConfig returns all currently known persistent clients as objects for the
// configuration file.
func (clients *clientsContainer) forConfig() (objs []*clientObject) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	objs = make([]*clientObject, 0, len(clients.list))
	for _, cli := range clients.list {
		o := &clientObject{
			Name: cli.Name,

			BlockedServices: cli.BlockedServices.Clone(),

			IDs:       stringutil.CloneSlice(cli.IDs),
			Tags:      stringutil.CloneSlice(cli.Tags),
			Upstreams: stringutil.CloneSlice(cli.Upstreams),

			UseGlobalSettings:        !cli.UseOwnSettings,
			FilteringEnabled:         cli.FilteringEnabled,
			ParentalEnabled:          cli.ParentalEnabled,
			SafeSearchConf:           cli.safeSearchConf,
			SafeBrowsingEnabled:      cli.SafeBrowsingEnabled,
			UseGlobalBlockedServices: !cli.UseOwnBlockedServices,
			IgnoreQueryLog:           cli.IgnoreQueryLog,
			IgnoreStatistics:         cli.IgnoreStatistics,
			UpstreamsCacheEnabled:    cli.UpstreamsCacheEnabled,
			UpstreamsCacheSize:       cli.UpstreamsCacheSize,
		}

		objs = append(objs, o)
	}

	// Maps aren't guaranteed to iterate in the same order each time, so the
	// above loop can generate different orderings when writing to the config
	// file: this produces lots of diffs in config files, so sort objects by
	// name before writing.
	slices.SortStableFunc(objs, func(a, b *clientObject) (res int) {
		return strings.Compare(a.Name, b.Name)
	})

	return objs
}

// arpClientsUpdatePeriod defines how often ARP clients are updated.
const arpClientsUpdatePeriod = 10 * time.Minute

func (clients *clientsContainer) periodicUpdate() {
	defer log.OnPanic("clients container")

	for {
		clients.reloadARP()
		time.Sleep(arpClientsUpdatePeriod)
	}
}

// clientSource checks if client with this IP address already exists and returns
// the source which updated it last.  It returns [client.SourceNone] if the
// client doesn't exist.
func (clients *clientsContainer) clientSource(ip netip.Addr) (src client.Source) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	_, ok := clients.findLocked(ip.String())
	if ok {
		return client.SourcePersistent
	}

	rc, ok := clients.ipToRC[ip]
	if ok {
		src, _ = rc.Info()
	}

	if src < client.SourceDHCP && clients.dhcp.HostByIP(ip) != "" {
		src = client.SourceDHCP
	}

	return src
}

// findMultiple is a wrapper around Find to make it a valid client finder for
// the query log.  c is never nil; if no information about the client is found,
// it returns an artificial client record by only setting the blocking-related
// fields.  err is always nil.
func (clients *clientsContainer) findMultiple(ids []string) (c *querylog.Client, err error) {
	var artClient *querylog.Client
	var art bool
	for _, id := range ids {
		ip, _ := netip.ParseAddr(id)
		c, art = clients.clientOrArtificial(ip, id)
		if art {
			artClient = c

			continue
		}

		return c, nil
	}

	return artClient, nil
}

// clientOrArtificial returns information about one client.  If art is true,
// this is an artificial client record, meaning that we currently don't have any
// records about this client besides maybe whether or not it is blocked.  c is
// never nil.
func (clients *clientsContainer) clientOrArtificial(
	ip netip.Addr,
	id string,
) (c *querylog.Client, art bool) {
	defer func() {
		c.Disallowed, c.DisallowedRule = clients.dnsServer.IsBlockedClient(ip, id)
		if c.WHOIS == nil {
			c.WHOIS = &whois.Info{}
		}
	}()

	cli, ok := clients.Find(id)
	if ok {
		return &querylog.Client{
			Name:           cli.Name,
			IgnoreQueryLog: cli.IgnoreQueryLog,
		}, false
	}

	var rc *client.Runtime
	rc, ok = clients.findRuntimeClient(ip)
	if ok {
		_, host := rc.Info()

		return &querylog.Client{
			Name:  host,
			WHOIS: rc.WHOIS(),
		}, false
	}

	return &querylog.Client{
		Name: "",
	}, true
}

// Find returns a shallow copy of the client if there is one found.
func (clients *clientsContainer) Find(id string) (c *Client, ok bool) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	c, ok = clients.findLocked(id)
	if !ok {
		return nil, false
	}

	return c.ShallowClone(), true
}

// shouldCountClient is a wrapper around Find to make it a valid client
// information finder for the statistics.  If no information about the client
// is found, it returns true.
func (clients *clientsContainer) shouldCountClient(ids []string) (y bool) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	for _, id := range ids {
		client, ok := clients.findLocked(id)
		if ok {
			return !client.IgnoreStatistics
		}
	}

	return true
}

// type check
var _ dnsforward.ClientsContainer = (*clientsContainer)(nil)

// UpstreamConfigByID implements the [dnsforward.ClientsContainer] interface for
// *clientsContainer.  upsConf is nil if the client isn't found or if the client
// has no custom upstreams.
func (clients *clientsContainer) UpstreamConfigByID(
	id string,
	bootstrap upstream.Resolver,
) (conf *proxy.CustomUpstreamConfig, err error) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	c, ok := clients.findLocked(id)
	if !ok {
		return nil, nil
	} else if c.upstreamConfig != nil {
		return c.upstreamConfig, nil
	}

	upstreams := stringutil.FilterOut(c.Upstreams, dnsforward.IsCommentOrEmpty)
	if len(upstreams) == 0 {
		return nil, nil
	}

	var upsConf *proxy.UpstreamConfig
	upsConf, err = proxy.ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			Bootstrap:    bootstrap,
			Timeout:      config.DNS.UpstreamTimeout.Duration,
			HTTPVersions: dnsforward.UpstreamHTTPVersions(config.DNS.UseHTTP3Upstreams),
			PreferIPv6:   config.DNS.BootstrapPreferIPv6,
		},
	)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	conf = proxy.NewCustomUpstreamConfig(
		upsConf,
		c.UpstreamsCacheEnabled,
		int(c.UpstreamsCacheSize),
		config.DNS.EDNSClientSubnet.Enabled,
	)
	c.upstreamConfig = conf

	return conf, nil
}

// findLocked searches for a client by its ID.  clients.lock is expected to be
// locked.
func (clients *clientsContainer) findLocked(id string) (c *Client, ok bool) {
	c, ok = clients.idIndex[id]
	if ok {
		return c, true
	}

	ip, err := netip.ParseAddr(id)
	if err != nil {
		return nil, false
	}

	for _, c = range clients.list {
		for _, id := range c.IDs {
			var subnet netip.Prefix
			subnet, err = netip.ParsePrefix(id)
			if err != nil {
				continue
			}

			if subnet.Contains(ip) {
				return c, true
			}
		}
	}

	// TODO(e.burkov):  Iterate through clients.list only once.
	return clients.findDHCP(ip)
}

// findDHCP searches for a client by its MAC, if the DHCP server is active and
// there is such client.  clients.lock is expected to be locked.
func (clients *clientsContainer) findDHCP(ip netip.Addr) (c *Client, ok bool) {
	foundMAC := clients.dhcp.MACByIP(ip)
	if foundMAC == nil {
		return nil, false
	}

	for _, c = range clients.list {
		for _, id := range c.IDs {
			mac, err := net.ParseMAC(id)
			if err != nil {
				continue
			}

			if bytes.Equal(mac, foundMAC) {
				return c, true
			}
		}
	}

	return nil, false
}

// runtimeClient returns a runtime client from internal index.  Note that it
// doesn't include DHCP clients.
func (clients *clientsContainer) runtimeClient(ip netip.Addr) (rc *client.Runtime, ok bool) {
	if ip == (netip.Addr{}) {
		return nil, false
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	rc, ok = clients.ipToRC[ip]

	return rc, ok
}

// findRuntimeClient finds a runtime client by their IP.
func (clients *clientsContainer) findRuntimeClient(ip netip.Addr) (rc *client.Runtime, ok bool) {
	rc, ok = clients.runtimeClient(ip)
	host := clients.dhcp.HostByIP(ip)

	if host != "" {
		if !ok {
			rc = &client.Runtime{}
		}

		rc.SetInfo(client.SourceDHCP, []string{host})

		return rc, true
	}

	return rc, ok
}

// check validates the client.
func (clients *clientsContainer) check(c *Client) (err error) {
	switch {
	case c == nil:
		return errors.Error("client is nil")
	case c.Name == "":
		return errors.Error("invalid name")
	case len(c.IDs) == 0:
		return errors.Error("id required")
	default:
		// Go on.
	}

	for i, id := range c.IDs {
		var norm string
		norm, err = normalizeClientIdentifier(id)
		if err != nil {
			return fmt.Errorf("client at index %d: %w", i, err)
		}

		c.IDs[i] = norm
	}

	for _, t := range c.Tags {
		if !clients.allTags.Has(t) {
			return fmt.Errorf("invalid tag: %q", t)
		}
	}

	slices.Sort(c.Tags)

	_, err = proxy.ParseUpstreamsConfig(c.Upstreams, &upstream.Options{})
	if err != nil {
		return fmt.Errorf("invalid upstream servers: %w", err)
	}

	return nil
}

// normalizeClientIdentifier returns a normalized version of idStr.  If idStr
// cannot be normalized, it returns an error.
func normalizeClientIdentifier(idStr string) (norm string, err error) {
	if idStr == "" {
		return "", errors.Error("clientid is empty")
	}

	var ip netip.Addr
	if ip, err = netip.ParseAddr(idStr); err == nil {
		return ip.String(), nil
	}

	var subnet netip.Prefix
	if subnet, err = netip.ParsePrefix(idStr); err == nil {
		return subnet.String(), nil
	}

	var mac net.HardwareAddr
	if mac, err = net.ParseMAC(idStr); err == nil {
		return mac.String(), nil
	}

	if err = dnsforward.ValidateClientID(idStr); err == nil {
		return strings.ToLower(idStr), nil
	}

	return "", fmt.Errorf("bad client identifier %q", idStr)
}

// Add adds a new client object.  ok is false if such client already exists or
// if an error occurred.
func (clients *clientsContainer) Add(c *Client) (ok bool, err error) {
	err = clients.check(c)
	if err != nil {
		return false, err
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	// check Name index
	_, ok = clients.list[c.Name]
	if ok {
		return false, nil
	}

	// check ID index
	for _, id := range c.IDs {
		var c2 *Client
		c2, ok = clients.idIndex[id]
		if ok {
			return false, fmt.Errorf("another client uses the same ID (%q): %q", id, c2.Name)
		}
	}

	clients.add(c)

	log.Debug("clients: added %q: ID:%q [%d]", c.Name, c.IDs, len(clients.list))

	return true, nil
}

// add c to the indexes. clients.lock is expected to be locked.
func (clients *clientsContainer) add(c *Client) {
	// update Name index
	clients.list[c.Name] = c

	// update ID index
	for _, id := range c.IDs {
		clients.idIndex[id] = c
	}
}

// Del removes a client.  ok is false if there is no such client.
func (clients *clientsContainer) Del(name string) (ok bool) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	var c *Client
	c, ok = clients.list[name]
	if !ok {
		return false
	}

	clients.del(c)

	return true
}

// del removes c from the indexes. clients.lock is expected to be locked.
func (clients *clientsContainer) del(c *Client) {
	if err := c.closeUpstreams(); err != nil {
		log.Error("client container: removing client %s: %s", c.Name, err)
	}

	// Update the name index.
	delete(clients.list, c.Name)

	// Update the ID index.
	for _, id := range c.IDs {
		delete(clients.idIndex, id)
	}
}

// Update updates a client by its name.
func (clients *clientsContainer) Update(prev, c *Client) (err error) {
	err = clients.check(c)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	// Check the name index.
	if prev.Name != c.Name {
		_, ok := clients.list[c.Name]
		if ok {
			return errors.Error("client already exists")
		}
	}

	// Check the ID index.
	if !slices.Equal(prev.IDs, c.IDs) {
		for _, id := range c.IDs {
			existing, ok := clients.idIndex[id]
			if ok && existing != prev {
				return fmt.Errorf("id %q is used by client with name %q", id, existing.Name)
			}
		}
	}

	clients.del(prev)
	clients.add(c)

	return nil
}

// setWHOISInfo sets the WHOIS information for a client.  clients.lock is
// expected to be locked.
func (clients *clientsContainer) setWHOISInfo(ip netip.Addr, wi *whois.Info) {
	_, ok := clients.findLocked(ip.String())
	if ok {
		log.Debug("clients: client for %s is already created, ignore whois info", ip)

		return
	}

	rc, ok := clients.ipToRC[ip]
	if !ok {
		// Create a RuntimeClient implicitly so that we don't do this check
		// again.
		rc = &client.Runtime{}
		clients.ipToRC[ip] = rc

		log.Debug("clients: set whois info for runtime client with ip %s: %+v", ip, wi)
	} else {
		host, _ := rc.Info()
		log.Debug("clients: set whois info for runtime client %s: %+v", host, wi)
	}

	rc.SetWHOIS(wi)
}

// addHost adds a new IP-hostname pairing.  The priorities of the sources are
// taken into account.  ok is true if the pairing was added.
//
// TODO(a.garipov): Only used in internal tests.  Consider removing.
func (clients *clientsContainer) addHost(
	ip netip.Addr,
	host string,
	src client.Source,
) (ok bool) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	return clients.addHostLocked(ip, host, src)
}

// type check
var _ client.AddressUpdater = (*clientsContainer)(nil)

// UpdateAddress implements the [client.AddressUpdater] interface for
// *clientsContainer
func (clients *clientsContainer) UpdateAddress(ip netip.Addr, host string, info *whois.Info) {
	// Common fast path optimization.
	if host == "" && info == nil {
		return
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	if host != "" {
		ok := clients.addHostLocked(ip, host, client.SourceRDNS)
		if !ok {
			log.Debug("clients: host for client %q already set with higher priority source", ip)
		}
	}

	if info != nil {
		clients.setWHOISInfo(ip, info)
	}
}

// addHostLocked adds a new IP-hostname pairing.  clients.lock is expected to be
// locked.
func (clients *clientsContainer) addHostLocked(
	ip netip.Addr,
	host string,
	src client.Source,
) (ok bool) {
	rc, ok := clients.ipToRC[ip]
	if !ok {
		if src < client.SourceDHCP {
			if clients.dhcp.HostByIP(ip) != "" {
				return false
			}
		}

		rc = &client.Runtime{}
		clients.ipToRC[ip] = rc
	}

	rc.SetInfo(src, []string{host})

	log.Debug("clients: adding client info %s -> %q %q [%d]", ip, src, host, len(clients.ipToRC))

	return true
}

// rmHostsBySrc removes all entries that match the specified source.
func (clients *clientsContainer) rmHostsBySrc(src client.Source) {
	n := 0
	for ip, rc := range clients.ipToRC {
		rc.Unset(src)
		if rc.IsEmpty() {
			delete(clients.ipToRC, ip)
			n++
		}
	}

	log.Debug("clients: removed %d client aliases", n)
}

// addFromHostsFile fills the client-hostname pairing index from the system's
// hosts files.
func (clients *clientsContainer) addFromHostsFile(hosts *hostsfile.DefaultStorage) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	clients.rmHostsBySrc(client.SourceHostsFile)

	n := 0
	hosts.RangeNames(func(addr netip.Addr, names []string) (cont bool) {
		// Only the first name of the first record is considered a canonical
		// hostname for the IP address.
		//
		// TODO(e.burkov):  Consider using all the names from all the records.
		if clients.addHostLocked(addr, names[0], client.SourceHostsFile) {
			n++
		}

		return true
	})

	log.Debug("clients: added %d client aliases from system hosts file", n)
}

// addFromSystemARP adds the IP-hostname pairings from the output of the arp -a
// command.
func (clients *clientsContainer) addFromSystemARP() {
	if err := clients.arpDB.Refresh(); err != nil {
		log.Error("refreshing arp container: %s", err)

		clients.arpDB = arpdb.Empty{}

		return
	}

	ns := clients.arpDB.Neighbors()
	if len(ns) == 0 {
		log.Debug("refreshing arp container: the update is empty")

		return
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	clients.rmHostsBySrc(client.SourceARP)

	added := 0
	for _, n := range ns {
		if clients.addHostLocked(n.IP, n.Name, client.SourceARP) {
			added++
		}
	}

	log.Debug("clients: added %d client aliases from arp neighborhood", added)
}

// close gracefully closes all the client-specific upstream configurations of
// the persistent clients.
func (clients *clientsContainer) close() (err error) {
	persistent := maps.Values(clients.list)
	slices.SortFunc(persistent, func(a, b *Client) (res int) {
		return strings.Compare(a.Name, b.Name)
	})

	var errs []error

	for _, cli := range persistent {
		if err = cli.closeUpstreams(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
