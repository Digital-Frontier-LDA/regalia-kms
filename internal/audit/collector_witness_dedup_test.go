package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ONE WITNESS PAIR PER NODE, WHATEVER THE NUMBER OF IDENTITIES (regalia-kms-dx7.9, PR #783
// CodeRabbit r4685272669): streams are keyed by (identity, site), and the site header is checked
// only for its charset, so two client certificates shipping under one site name hold two streams
// for one node. The endpoint must still emit exactly one series per gauge per site: a duplicate
// metric-name/label set makes the scrape's value undefined, in the very series the
// behind-the-collector rules compare against. The value is the HIGHEST epoch any identity's
// committed trail holds for the site: the behind rules fire when the node is below the witness,
// so the maximum is the sensitive choice. Covered: the higher epoch on either identity (nodea:
// the second identity is ahead on sync, the FIRST on esp-advances), a tie (nodeb), and the sites
// emitted in sorted order whatever the map's order.
func TestTheMetricsEndpointEmitsOneWitnessPairPerSiteAcrossIdentities(t *testing.T) {
	collector, err := OpenCollector(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()

	commitTrail := func(identity, stream string, epochs ...int) {
		t.Helper()
		var data strings.Builder
		prev := ""
		for i, epoch := range epochs {
			line := `{"at":` + strconv.Itoa(1790000000+i) + `,"event":"epoch","prev":"` + prev + `","seq":` + strconv.Itoa(i+1) + `,"outcome":"ALLOW","epoch":` + strconv.Itoa(epoch) + `}`
			sum := sha256.Sum256([]byte(line + "\n"))
			prev = hex.EncodeToString(sum[:])
			data.WriteString(line + "\n")
		}
		trail := stream[strings.LastIndexByte(stream, '.')+1:]
		events, err := TrailEvents(trail, []byte(data.String()))
		if err != nil {
			t.Fatalf("the %s trail does not map: %v", stream, err)
		}
		for _, event := range events {
			if status, _, message := collector.commit(identity, stream, event); status != http.StatusNoContent {
				t.Fatalf("commit %s for %s: %d %s", stream, identity[:8], status, message)
			}
		}
	}
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	commitTrail(first, "nodea.sync", 3, 5)
	commitTrail(first, "nodea.esp-advances", 4)
	commitTrail(second, "nodea.sync", 6, 9)
	commitTrail(second, "nodea.esp-advances", 2, 3)
	commitTrail(second, "nodeb.sync", 4)
	commitTrail(first, "nodeb.sync", 4)
	commitTrail(first, "nodeb.esp-advances", 1)

	recorder := httptest.NewRecorder()
	collector.MetricsHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(recorder.Result().Body)

	series := map[string]int{}
	for _, line := range strings.Split(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line[:strings.LastIndexByte(line, ' ')]
		series[name]++
		if series[name] > 1 {
			t.Fatalf("the endpoint emits %s more than once: the scrape's value is undefined\n%s", name, body)
		}
	}
	want := map[string]string{
		`regalia_collector_witnessed_membership_epoch{site="nodea"}`: "9",
		`regalia_collector_witnessed_anchor_epoch{site="nodea"}`:     "4",
		`regalia_collector_witnessed_membership_epoch{site="nodeb"}`: "4",
		`regalia_collector_witnessed_anchor_epoch{site="nodeb"}`:     "1",
	}
	for name, value := range want {
		if !strings.Contains(string(body), name+" "+value+"\n") {
			t.Fatalf("want %s %s (the highest epoch any identity committed for the site):\n%s", name, value, body)
		}
	}
	if a, b := strings.Index(string(body), `{site="nodea"}`), strings.Index(string(body), `{site="nodeb"}`); a < 0 || b < 0 || a > b {
		t.Fatalf("the sites are not emitted in sorted order (nodea before nodeb):\n%s", body)
	}
	if len(series) != len(want) {
		t.Fatalf("want exactly %d series, got %d:\n%s", len(want), len(series), body)
	}
}

// witnessFixture is a collector with helpers to commit a trail of ALLOW epochs under an identity
// and to scrape the metrics endpoint.
type witnessFixture struct {
	t         *testing.T
	collector *Collector
}

func newWitnessFixture(t *testing.T) *witnessFixture {
	t.Helper()
	collector, err := OpenCollector(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { collector.Close() })
	return &witnessFixture{t: t, collector: collector}
}

func (f *witnessFixture) commit(identity, stream string, epochs ...int) {
	f.t.Helper()
	var data strings.Builder
	prev := ""
	for i, epoch := range epochs {
		line := `{"at":` + strconv.Itoa(1790000000+i) + `,"event":"epoch","prev":"` + prev + `","seq":` + strconv.Itoa(i+1) + `,"outcome":"ALLOW","epoch":` + strconv.Itoa(epoch) + `}`
		sum := sha256.Sum256([]byte(line + "\n"))
		prev = hex.EncodeToString(sum[:])
		data.WriteString(line + "\n")
	}
	events, err := TrailEvents(stream[strings.LastIndexByte(stream, '.')+1:], []byte(data.String()))
	if err != nil {
		f.t.Fatalf("the %s trail does not map: %v", stream, err)
	}
	for _, event := range events {
		if status, _, message := f.collector.commit(identity, stream, event); status != http.StatusNoContent {
			f.t.Fatalf("commit %s for %s: %d %s", stream, identity[:8], status, message)
		}
	}
}

func (f *witnessFixture) scrape() string {
	f.t.Helper()
	recorder := httptest.NewRecorder()
	f.collector.MetricsHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(recorder.Result().Body)
	return string(body)
}

// THE SITES COME OUT IN SORTED ORDER (GA nit A on #783): with five sites committed in a
// non-sorted order, the series are emitted nodea..nodee exactly. Two sites would catch a dropped
// sort only about half the time (Go's map order is random); five make a passing unsorted run
// vanishingly unlikely.
func TestTheMetricsEndpointEmitsSitesInSortedOrder(t *testing.T) {
	f := newWitnessFixture(t)
	identity := strings.Repeat("c", 64)
	for _, site := range []string{"noded", "nodeb", "nodee", "nodea", "nodec"} {
		f.commit(identity, site+".sync", 1)
	}
	var got []string
	for _, line := range strings.Split(f.scrape(), "\n") {
		if strings.HasPrefix(line, "regalia_collector_witnessed_membership_epoch{") {
			got = append(got, line[strings.Index(line, `"`)+1:strings.LastIndex(line, `"`)])
		}
	}
	if strings.Join(got, ",") != "nodea,nodeb,nodec,noded,nodee" {
		t.Fatalf("the sites are not emitted in sorted order: %v", got)
	}
}

// A STREAM THAT CANNOT BE READ THROUGH ITS COMMITTED SIZE REPORTS NO VALUE (PR #783 CodeRabbit
// r4685272685 follow-up, regalia-kms-1gv): a partial walk may have missed the highest epoch, so
// publishing what it found would invent a floor. Here the stream file ends before its committed
// size, after its first line (epoch 3) and before its second (epoch 7): the site reports no
// membership series at all — not 3.
func TestAWitnessStreamShorterThanItsCommittedSizeReportsNoValue(t *testing.T) {
	f := newWitnessFixture(t)
	identity := strings.Repeat("d", 64)
	f.commit(identity, "nodea.sync", 3, 7)
	truncateToFirstLine(t, f.collector.streamPath(identity, "nodea.sync"))
	if body := f.scrape(); strings.Contains(body, "regalia_collector_witnessed_membership_epoch{") {
		t.Fatalf("a stream read only partly published a value (it must report absence):\n%s", body)
	}
}

// ONE UNREADABLE IDENTITY BLINDS THE WHOLE SITE (regalia-kms-1gv): two identities hold nodea's
// sync trail; the one holding the HIGHER epoch (9) cannot be read through its committed size.
// Reporting the readable identity's 5 would lower the floor the behind rules compare against and
// hide a rollback to 6..8; the site must report no value instead.
func TestAnUnreadableIdentityStreamBlindsTheSiteRatherThanLoweringIt(t *testing.T) {
	f := newWitnessFixture(t)
	low, high := strings.Repeat("e", 64), strings.Repeat("f", 64)
	f.commit(low, "nodea.sync", 3, 5)
	f.commit(high, "nodea.sync", 6, 9)
	truncateToFirstLine(t, f.collector.streamPath(high, "nodea.sync"))
	if body := f.scrape(); strings.Contains(body, `regalia_collector_witnessed_membership_epoch{site="nodea"}`) {
		t.Fatalf("an unreadable stream let the site publish the other identity's lower epoch:\n%s", body)
	}
}

func truncateToFirstLine(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.IndexByte(string(data), '\n')
	if first < 0 || first+1 >= len(data) {
		t.Fatalf("%s does not hold two lines", path)
	}
	if err := os.Truncate(path, int64(first+1)); err != nil {
		t.Fatal(err)
	}
}
