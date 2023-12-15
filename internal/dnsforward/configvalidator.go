package dnsforward

import (
	"fmt"
	"sync"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// upstreamConfigValidator parses the [*proxy.UpstreamConfig] and checks the
// actual DNS availability of each upstream.
type upstreamConfigValidator struct {
	// general is the general upstream configuration.
	general map[string]*upstreamResult

	// fallback is the fallback upstream configuration.
	fallback map[string]*upstreamResult

	// private is the private upstream configuration.
	private map[string]*upstreamResult
}

// upstreamResult is a result of validation of an [upstream.Upstream] within an
// [proxy.UpstreamConfig].
type upstreamResult struct {
	// server is the parsed upstream.  It is nil when there was an error during
	// parsing.
	server upstream.Upstream

	// err is the error either from parsing or from checking the upstream.
	err error

	// isSpecific is true if the upstream is domain-specific.
	isSpecific bool
}

// newUpstreamConfigValidator parses the upstream configuration and returns a
// validator for it.  cv already contains the parsed upstreams along with errors
// related.
func newUpstreamConfigValidator(
	general []string,
	fallback []string,
	private []string,
	opts *upstream.Options,
) (cv *upstreamConfigValidator) {
	cv = &upstreamConfigValidator{
		general:  map[string]*upstreamResult{},
		fallback: map[string]*upstreamResult{},
		private:  map[string]*upstreamResult{},
	}

	conf, err := proxy.ParseUpstreamsConfig(general, opts)
	if err != nil {
		cv.insertErrResults(cv.general, "Upstream DNS Servers", err)
	}
	cv.insertConfResults(cv.general, conf)

	conf, err = proxy.ParseUpstreamsConfig(fallback, opts)
	if err != nil {
		cv.insertErrResults(cv.fallback, "Fallback DNS Servers", err)
	}
	cv.insertConfResults(cv.fallback, conf)

	conf, err = proxy.ParseUpstreamsConfig(private, opts)
	if err != nil {
		cv.insertErrResults(cv.private, "Private DNS Servers", err)
	}
	cv.insertConfResults(cv.private, conf)

	return cv
}

// insertErrResults parses err and inserts the result into s.  It can insert
// multiple results as well as none.
func (cv *upstreamConfigValidator) insertErrResults(
	m map[string]*upstreamResult,
	section string,
	err error,
) {
	wrapper, ok := err.(errors.WrapperSlice)
	if !ok {
		log.Debug("dnsforward: unwrapping: %s", err)

		return
	}

	errs := wrapper.Unwrap()
	for _, e := range errs {
		var parseErr *proxy.ParseError
		if !errors.As(e, &parseErr) {
			log.Debug("dnsforward: inserting: %s", err)

			continue
		}

		idx := parseErr.Idx

		original := fmt.Sprintf("Line: %d %s", idx+1, section)
		m[original] = &upstreamResult{err: errors.Unwrap(e)}
	}
}

// insertConfResults parses conf and inserts the result into s.  It can insert
// multiple results as well as none.
func (cv *upstreamConfigValidator) insertConfResults(
	m map[string]*upstreamResult,
	conf *proxy.UpstreamConfig,
) {
	cv.insertListResults(m, conf.Upstreams, false)

	for _, ups := range conf.DomainReservedUpstreams {
		cv.insertListResults(m, ups, true)
	}

	for _, ups := range conf.SpecifiedDomainUpstreams {
		cv.insertListResults(m, ups, true)
	}
}

// insertListResults constructs upstream results from the upstream list and
// inserts into s.  It can insert multiple results as well as none.
func (cv *upstreamConfigValidator) insertListResults(
	m map[string]*upstreamResult,
	ups []upstream.Upstream,
	specific bool,
) {
	for _, u := range ups {
		addr := u.Address()
		_, ok := m[addr]
		if ok {
			continue
		}

		m[addr] = &upstreamResult{
			server:     u,
			isSpecific: specific,
		}
	}
}

// check tries to exchange with each successfully parsed upstream and enriches
// the results with the healthcheck errors.  It should not be called after the
// [upsConfValidator.close] method, since it makes no sense to check the closed
// upstreams.
func (cv *upstreamConfigValidator) check() {
	const (
		// testTLD is the special-use fully-qualified domain name for testing
		// the DNS server reachability.
		//
		// See https://datatracker.ietf.org/doc/html/rfc6761#section-6.2.
		testTLD = "test."

		// inAddrARPATLD is the special-use fully-qualified domain name for PTR
		// IP address resolution.
		//
		// See https://datatracker.ietf.org/doc/html/rfc1035#section-3.5.
		inAddrARPATLD = "in-addr.arpa."
	)

	commonChecker := &healthchecker{
		hostname: testTLD,
		qtype:    dns.TypeA,
		ansEmpty: true,
	}

	arpaChecker := &healthchecker{
		hostname: inAddrARPATLD,
		qtype:    dns.TypePTR,
		ansEmpty: false,
	}

	wg := &sync.WaitGroup{}
	wg.Add(len(cv.general) + len(cv.fallback) + len(cv.private))

	for _, res := range cv.general {
		go cv.checkSrv(res, wg, commonChecker)
	}
	for _, res := range cv.fallback {
		go cv.checkSrv(res, wg, commonChecker)
	}
	for _, res := range cv.private {
		go cv.checkSrv(res, wg, arpaChecker)
	}

	wg.Wait()
}

// checkSrv runs hc on the server from res, if any, and stores any occurred
// error in res.  wg is always marked done in the end.  It used to be called in
// a separate goroutine.
func (cv *upstreamConfigValidator) checkSrv(
	res *upstreamResult,
	wg *sync.WaitGroup,
	hc *healthchecker,
) {
	defer wg.Done()

	if res.server == nil {
		return
	}

	res.err = hc.check(res.server)
	if res.err != nil && res.isSpecific {
		res.err = domainSpecificTestError{Err: res.err}
	}
}

// close closes all the upstreams that were successfully parsed.  It enriches
// the results with deferred closing errors.
func (cv *upstreamConfigValidator) close() {
	all := []map[string]*upstreamResult{cv.general, cv.fallback, cv.private}

	for _, m := range all {
		for _, r := range m {
			if r.server != nil {
				r.err = errors.WithDeferred(r.err, r.server.Close())
			}
		}
	}
}

// status returns all the data collected during parsing, healthcheck, and
// closing of the upstreams.  The returned map is keyed by the original upstream
// configuration piece and contains the corresponding error or "OK" if there was
// no error.
func (cv *upstreamConfigValidator) status() (results map[string]string) {
	result := map[string]string{}

	for original, res := range cv.general {
		resultToStatus("general", original, res, result)
	}
	for original, res := range cv.fallback {
		resultToStatus("fallback", original, res, result)
	}
	for original, res := range cv.private {
		resultToStatus("private", original, res, result)
	}

	return result
}

// resultToStatus puts "OK" or an error message from res into resMap.  section
// is the name of the upstream configuration section, i.e. "general",
// "fallback", or "private", and only used for logging.
//
// TODO(e.burkov):  Currently, the HTTP handler expects that all the results are
// put together in a single map, which may lead to collisions, see AG-27539.
// Improve the results compilation.
func resultToStatus(
	section string,
	original string,
	res *upstreamResult,
	resMap map[string]string,
) {
	val := "OK"
	if res.err != nil {
		val = res.err.Error()
	}

	prevVal := resMap[original]
	switch prevVal {
	case "":
		resMap[original] = val
	case val:
		log.Debug("dnsforward: duplicating %s config line %q", section, original)
	default:
		log.Debug(
			"dnsforward: warning: %s config line %q (%v) had different result %v",
			section,
			val,
			original,
			prevVal,
		)
	}
}

// domainSpecificTestError is a wrapper for errors returned by checkDNS to mark
// the tested upstream domain-specific and therefore consider its errors
// non-critical.
//
// TODO(a.garipov):  Some common mechanism of distinguishing between errors and
// warnings (non-critical errors) is desired.
type domainSpecificTestError struct {
	// Err is the actual error occurred during healthcheck test.
	Err error
}

// type check
var _ error = domainSpecificTestError{}

// Error implements the [error] interface for domainSpecificTestError.
func (err domainSpecificTestError) Error() (msg string) {
	return fmt.Sprintf("WARNING: %s", err.Err)
}

// type check
var _ errors.Wrapper = domainSpecificTestError{}

// Unwrap implements the [errors.Wrapper] interface for domainSpecificTestError.
func (err domainSpecificTestError) Unwrap() (wrapped error) {
	return err.Err
}

// healthchecker checks the upstream's status by exchanging with it.
type healthchecker struct {
	// hostname is the name of the host to put into healthcheck DNS request.
	hostname string

	// qtype is the type of DNS request to use for healthcheck.
	qtype uint16

	// ansEmpty defines if the answer section within the response is expected to
	// be empty.
	ansEmpty bool
}

// check exchanges with u and validates the response.
func (h *healthchecker) check(u upstream.Upstream) (err error) {
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   h.hostname,
			Qtype:  h.qtype,
			Qclass: dns.ClassINET,
		}},
	}

	reply, err := u.Exchange(req)
	if err != nil {
		return fmt.Errorf("couldn't communicate with upstream: %w", err)
	} else if h.ansEmpty && len(reply.Answer) > 0 {
		return errWrongResponse
	}

	return nil
}
