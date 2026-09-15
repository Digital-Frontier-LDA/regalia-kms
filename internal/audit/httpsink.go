package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var auditHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// HTTPSink synchronously ships an event to a dedicated off-host collector.
// Success requires an acknowledgement of the exact chained event hash; a 2xx
// status by itself is insufficient evidence that the collector committed it.
type HTTPSink struct {
	baseURL string
	client  *http.Client
	timeout time.Duration
	// site names the stream the collector files this host's events under (identity plus
	// the X-Regalia-Site header, per doc/AUDIT-COLLECTOR-RECONCILIATION.md). It travels
	// on every Send AND must equal the site passed to CommittedHead at reconciliation:
	// a sink shipping site-less while reconciling site "sitea" asks about a stream its
	// own events never went to, and every restart would refuse as "collector forgot" —
	// a defect the end-to-end collector test exists to catch, because each half alone
	// looks correct.
	site string
}

// ValidateSinkURL states what an audit collector address may be.
//
// The SOPS adapter's loadConfig applies the same rule to its kms_url and cannot share this code —
// it is a separate module and this package is internal. The two disagreed on a trailing slash until
// they were aligned; if you change the rule here, change it there.
//
// The sink appends its own paths ("/v1/events", "/v1/health/ready"), so the configured value is an
// ORIGIN, not an endpoint. A configured path would silently produce "/v1/events/v1/events" and ship
// the audit trail to a URL nobody chose. A bare trailing slash is the same origin written a second
// way, so it is accepted and normalized rather than refused — refusing it made a correct address
// look like a misconfiguration.
func ValidateSinkURL(baseURL string) error {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("audit collector must be an https origin")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("audit collector must be an origin with no path, got %q", parsed.Path)
	}
	return nil
}

// NewHTTPSink builds the sink. site is the X-Regalia-Site value the collector keys this
// host's stream by; an empty site is legal and names the identity-keyed stream — but it
// must then also be the empty site at reconciliation (ReconcileContinuity's site argument),
// or the two calls address different streams.
func NewHTTPSink(baseURL string, client *http.Client, timeout time.Duration, site string) (*HTTPSink, error) {
	if err := ValidateSinkURL(baseURL); err != nil || client == nil {
		return nil, errors.New("invalid audit collector configuration")
	}
	if timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, errors.New("invalid audit collector timeout")
	}
	if strings.ContainsAny(site, "\r\n") || len(site) > 64 {
		return nil, errors.New("invalid audit collector site")
	}
	copyClient := *client
	copyClient.Timeout = timeout
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPSink{baseURL: strings.TrimSuffix(baseURL, "/"), client: &copyClient, timeout: timeout, site: site}, nil
}

func (sink *HTTPSink) Send(ctx context.Context, event Event) error {
	if sink == nil || sink.client == nil || !auditHashPattern.MatchString(event.Hash) {
		return ErrSinkUnavailable
	}
	body, err := json.Marshal(event)
	if err != nil || len(body) > 64<<10 {
		return ErrSinkUnavailable
	}
	requestCtx, cancel := context.WithTimeout(ctx, sink.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, sink.baseURL+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return ErrSinkUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", event.Hash)
	if sink.site != "" {
		request.Header.Set("X-Regalia-Site", sink.site)
	}
	response, err := sink.client.Do(request)
	if err != nil {
		return ErrSinkUnavailable
	}
	if response.Body != nil {
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	}
	if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Regalia-Audit-Hash") != event.Hash {
		return ErrSinkUnavailable
	}
	return nil
}

// CommittedHead asks the collector for the last event it committed durably for this stream
// (doc/AUDIT-COLLECTOR-RECONCILIATION.md): the one position the host cannot author, used at
// startup to refuse a journal that disagrees with what this site already shipped. Same wire
// discipline as Send — bounded body, no redirects (the client was built with
// ErrUseLastResponse), and an answer that does not parse is an error, never a zero.
func (sink *HTTPSink) CommittedHead(ctx context.Context, site string) (uint64, string, error) {
	if sink == nil || sink.client == nil {
		return 0, "", ErrSinkUnavailable
	}
	requestCtx, cancel := context.WithTimeout(ctx, sink.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, sink.baseURL+"/v1/stream-position", nil)
	if err != nil {
		return 0, "", ErrSinkUnavailable
	}
	if site != "" {
		request.Header.Set("X-Regalia-Site", site)
	}
	request.Header.Set("Accept", "application/json")
	response, err := sink.client.Do(request)
	if err != nil {
		return 0, "", ErrSinkUnavailable
	}
	defer func() {
		if response.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
		}
	}()
	if response.StatusCode != http.StatusOK {
		return 0, "", ErrSinkUnavailable
	}
	var position struct {
		Sequence uint64 `json:"sequence"`
		Hash     string `json:"hash"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4096))
	if err := decoder.Decode(&position); err != nil {
		return 0, "", ErrSinkUnavailable
	}
	// NO SECOND DOCUMENT. Trailing data after a well-formed object is another answer
	// travelling alongside the one that was checked — the same rule as the SignDoc parser,
	// arriving over HTTP instead of protobuf.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, "", ErrSinkUnavailable
	}
	// THREE STATES, NOT TWO: (0, "") is "holds nothing"; (N, valid-hash) is a position.
	// A non-zero sequence with an empty hash — or a zero sequence with a hash — is a shape
	// the collector can never emit, and this head is authoritative in reconciliation: it is
	// the one value the host cannot author, so the sink must not hand the reconciler a
	// value in a shape its own source would not produce. "Answered something impossible"
	// is a third state and it refuses like the other two.
	if (position.Sequence > 0) != (position.Hash != "") || (position.Hash != "" && !auditHashPattern.MatchString(position.Hash)) {
		return 0, "", ErrSinkUnavailable
	}
	return position.Sequence, position.Hash, nil
}

func (sink *HTTPSink) Ready(ctx context.Context) bool {
	if sink == nil || sink.client == nil {
		return false
	}
	requestCtx, cancel := context.WithTimeout(ctx, sink.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodHead, sink.baseURL+"/v1/health/ready", nil)
	if err != nil {
		return false
	}
	response, err := sink.client.Do(request)
	if err != nil {
		return false
	}
	if response.Body != nil {
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	}
	return response.StatusCode == http.StatusNoContent
}
