package cosmosrpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const address = "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"

type chain struct {
	network, account string
	status           int
	nodeInfoCalls    atomic.Int32
}

func (c *chain) serve(t *testing.T) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cosmos/base/tendermint/v1beta1/node_info":
			c.nodeInfoCalls.Add(1)
			fmt.Fprintf(w, `{"default_node_info":{"network":%q}}`, c.network)
		case strings.HasPrefix(r.URL.Path, "/cosmos/auth/v1beta1/accounts/"):
			if c.status != 0 {
				w.WriteHeader(c.status)
				return
			}
			fmt.Fprint(w, c.account)
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	client, err := New(map[string]string{"cosmoshub-4": server.URL}, 2*time.Second, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func baseAccountJSON(addr, number, sequence string) string {
	return fmt.Sprintf(`{"account":{"@type":"/cosmos.auth.v1beta1.BaseAccount","address":%q,"pub_key":null,"account_number":%q,"sequence":%q}}`, addr, number, sequence)
}

func TestTheChainSaysTheAccountNumberAndSequence(t *testing.T) {
	c := &chain{network: "cosmoshub-4", account: baseAccountJSON(address, "42", "7")}
	client, _ := c.serve(t)
	got, err := client.Account(context.Background(), "cosmoshub-4", address)
	if err != nil || got != (Account{Address: address, AccountNumber: 42, Sequence: 7}) {
		t.Fatalf("%+v %v", got, err)
	}
	// a vesting account: its base account inside
	c.account = `{"account":{"@type":"/cosmos.vesting.v1beta1.ContinuousVestingAccount","base_vesting_account":{"base_account":` +
		`{"address":"` + address + `","account_number":"43","sequence":"9"}}}}`
	if got, err := client.Account(context.Background(), "cosmoshub-4", address); err != nil || got.AccountNumber != 43 || got.Sequence != 9 {
		t.Fatalf("vesting: %+v %v", got, err)
	}
	// the endpoint's chain was asked once, and is trusted for ChainCheckEvery
	if calls := c.nodeInfoCalls.Load(); calls != 1 {
		t.Fatalf("node_info asked %d times", calls)
	}
	client.now = func() time.Time { return time.Now().Add(ChainCheckEvery) }
	if _, err := client.Account(context.Background(), "cosmoshub-4", address); err != nil || c.nodeInfoCalls.Load() != 2 {
		t.Fatalf("the chain was not asked again after %s: %v", ChainCheckEvery, err)
	}
}

// Whatever the endpoint answers wrongly, the KMS learns nothing and signs nothing: ErrUnavailable.
func TestAnEndpointThatSaysNothingUsableIsUnavailable(t *testing.T) {
	for _, c := range []struct {
		name, network, account string
		status                 int
		want                   string
	}{
		{"another chain", "osmosis-1", baseAccountJSON(address, "42", "7"), 0, `serves chain "osmosis-1"`},
		{"another address", "cosmoshub-4", baseAccountJSON("cosmos1zzzzzzzzzzzzzzzzzz", "42", "7"), 0, "answered for"},
		{"an unknown account type", "cosmoshub-4", `{"account":{"@type":"/cosmos.auth.v1beta1.ModuleAccount","base_account":{}}}`, 0, "is not one this KMS reads"},
		{"a sequence that is not a number", "cosmoshub-4", baseAccountJSON(address, "42", "-1"), 0, "not a whole number"},
		{"an error status", "cosmoshub-4", "", 500, "HTTP 500"},
		{"not JSON", "cosmoshub-4", "<html>", 0, "not the expected JSON"},
		{"too large", "cosmoshub-4", `{"account":"` + strings.Repeat("a", MaxResponseBytes) + `"}`, 0, "more than"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ch := &chain{network: c.network, account: c.account, status: c.status}
			client, _ := ch.serve(t)
			_, err := client.Account(context.Background(), "cosmoshub-4", address)
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, not %q", err, c.want)
			}
		})
	}
	client, _ := (&chain{network: "cosmoshub-4"}).serve(t)
	for _, bad := range []string{"cosmos1/../../x", "COSMOS1ABC", ""} {
		if _, err := client.Account(context.Background(), "cosmoshub-4", bad); !errors.Is(err, ErrUnavailable) {
			t.Errorf("address %q: %v", bad, err)
		}
	}
	if _, err := client.Account(context.Background(), "osmosis-1", address); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an unconfigured chain: %v", err)
	}
}

func TestEndpointsAreHTTPSAndRedirectsAreNotFollowed(t *testing.T) {
	for _, bad := range []map[string]string{
		{"cosmoshub-4": "http://rpc.example"}, {"cosmoshub-4": "https://user:pw@rpc.example"}, {"cosmoshub-4": "https://rpc.example/?a=b"},
		{"cosmos hub": "https://rpc.example"}, {},
	} {
		if _, err := New(bad, time.Second, nil); err == nil {
			t.Errorf("%v taken", bad)
		}
	}
	ch := &chain{network: "cosmoshub-4"}
	client, _ := ch.serve(t)
	var into any
	if err := client.get(context.Background(), "cosmoshub-4", "/redirect", &into); err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Fatalf("a redirect: %v", err)
	}
}
