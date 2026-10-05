// Package cosmosrpc asks a Cosmos chain what it says about an account, for the cosmos-account signing profile
// (#432; the owner: the KMS is a blockchain user, not a validator). Before a cosmos-account key signs, the daemon
// fetches the signer's account number and sequence, and the chain's ID, and the policy requires the SignDoc to
// carry exactly those (d9's hole 3). The chain arbitrates the sequence; the KMS keeps no high-water state.
//
// THE ENDPOINT CAN ONLY DENY SERVICE. A lying or intercepted endpoint can make the values differ from the
// SignDoc's, and the KMS then refuses to sign; it cannot make the KMS sign anything the SignDoc and its policy
// would not allow, because equality is required, never substitution. Endpoints are pinned per chain in the
// configuration (HTTPS, normal certificate validation), and the host's egress names exactly those hosts.
package cosmosrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// MaxResponseBytes bounds what an endpoint may answer.
const MaxResponseBytes = 64 << 10

var (
	addressPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,82}1[02-9ac-hj-np-z]{6,90}$`) // bech32: hrp "1" data
	chainPattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,47}$`)
)

// ErrUnavailable is any failure to learn what the chain says: the KMS refuses to sign (fail closed), retryable.
var ErrUnavailable = errors.New("the chain's endpoint did not say")

// Account is what the chain says of an account.
type Account struct {
	Address       string
	AccountNumber uint64
	Sequence      uint64
}

// Client asks each configured chain's endpoint.
type Client struct {
	endpoints map[string]*url.URL
	http      *http.Client
	now       func() time.Time

	mu     sync.Mutex
	chains map[string]time.Time // chain ID -> when its endpoint last said it serves that chain
}

// ChainCheckEvery is how long an endpoint's own chain ID is trusted before it is asked again.
const ChainCheckEvery = 5 * time.Minute

// New validates the endpoints ({chain ID: https base URL}) and makes a client with `timeout` per request.
func New(endpoints map[string]string, timeout time.Duration, transport http.RoundTripper) (*Client, error) {
	if len(endpoints) == 0 || timeout <= 0 {
		return nil, errors.New("cosmosrpc: at least one chain endpoint and a timeout are required")
	}
	parsed := make(map[string]*url.URL, len(endpoints))
	for chain, raw := range endpoints {
		if !chainPattern.MatchString(chain) {
			return nil, fmt.Errorf("cosmosrpc: %q is not a chain ID", chain)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("cosmosrpc: the endpoint for %s must be an https URL with no credentials, query or fragment", chain)
		}
		parsed[chain] = u
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Client{endpoints: parsed, http: &http.Client{Timeout: timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") }},
		now: time.Now, chains: map[string]time.Time{}}, nil
}

func (c *Client) get(ctx context.Context, chain, path string, into any) error {
	base, ok := c.endpoints[chain]
	if !ok {
		return fmt.Errorf("%w: no endpoint is configured for chain %s", ErrUnavailable, chain)
	}
	target := *base
	target.Path = base.Path + path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, chain, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(body) > MaxResponseBytes {
		return fmt.Errorf("%w: %s answered more than %d bytes, or could not be read", ErrUnavailable, chain, MaxResponseBytes)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered HTTP %d", ErrUnavailable, chain, response.StatusCode)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%w: %s answered what is not the expected JSON: %v", ErrUnavailable, chain, err)
	}
	return nil
}

// checkChain asks the endpoint which chain it serves (node_info's network), at most every ChainCheckEvery: an
// endpoint serving another chain would give another chain's account numbers.
func (c *Client) checkChain(ctx context.Context, chain string) error {
	c.mu.Lock()
	checked, ok := c.chains[chain]
	c.mu.Unlock()
	if ok && c.now().Sub(checked) < ChainCheckEvery {
		return nil
	}
	var info struct {
		DefaultNodeInfo struct {
			Network string `json:"network"`
		} `json:"default_node_info"`
	}
	if err := c.get(ctx, chain, "/cosmos/base/tendermint/v1beta1/node_info", &info); err != nil {
		return err
	}
	if info.DefaultNodeInfo.Network != chain {
		return fmt.Errorf("%w: the endpoint for %s serves chain %q", ErrUnavailable, chain, info.DefaultNodeInfo.Network)
	}
	c.mu.Lock()
	c.chains[chain] = c.now()
	c.mu.Unlock()
	return nil
}

type baseAccount struct {
	Address       string `json:"address"`
	AccountNumber string `json:"account_number"`
	Sequence      string `json:"sequence"`
}

// Account fetches what `chain` says of `address`: /cosmos/auth/v1beta1/accounts/{address}. A BaseAccount, or the
// SDK's vesting accounts (their base account inside); any other account type is refused (fail closed).
func (c *Client) Account(ctx context.Context, chain, address string) (Account, error) {
	if !addressPattern.MatchString(address) {
		return Account{}, fmt.Errorf("%w: %q is not a bech32 address", ErrUnavailable, address)
	}
	if err := c.checkChain(ctx, chain); err != nil {
		return Account{}, err
	}
	var answer struct {
		Account json.RawMessage `json:"account"`
	}
	if err := c.get(ctx, chain, "/cosmos/auth/v1beta1/accounts/"+address, &answer); err != nil {
		return Account{}, err
	}
	base, err := baseOf(answer.Account)
	if err != nil {
		return Account{}, fmt.Errorf("%w: %s: %v", ErrUnavailable, chain, err)
	}
	if base.Address != address {
		return Account{}, fmt.Errorf("%w: %s answered for %q, not %q", ErrUnavailable, chain, base.Address, address)
	}
	number, err1 := strconv.ParseUint(base.AccountNumber, 10, 64)
	sequence, err2 := strconv.ParseUint(base.Sequence, 10, 64)
	if err1 != nil || err2 != nil {
		return Account{}, fmt.Errorf("%w: %s answered an account number or sequence that is not a whole number", ErrUnavailable, chain)
	}
	return Account{Address: address, AccountNumber: number, Sequence: sequence}, nil
}

func baseOf(raw json.RawMessage) (baseAccount, error) {
	var typed struct {
		Type string `json:"@type"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return baseAccount{}, errors.New("the account is not an object")
	}
	var base baseAccount
	switch typed.Type {
	case "/cosmos.auth.v1beta1.BaseAccount":
		if err := json.Unmarshal(raw, &base); err != nil {
			return baseAccount{}, err
		}
	case "/cosmos.vesting.v1beta1.ContinuousVestingAccount", "/cosmos.vesting.v1beta1.DelayedVestingAccount",
		"/cosmos.vesting.v1beta1.PeriodicVestingAccount", "/cosmos.vesting.v1beta1.PermanentLockedAccount":
		var vesting struct {
			BaseVestingAccount struct {
				BaseAccount baseAccount `json:"base_account"`
			} `json:"base_vesting_account"`
		}
		if err := json.Unmarshal(raw, &vesting); err != nil {
			return baseAccount{}, err
		}
		base = vesting.BaseVestingAccount.BaseAccount
	default:
		return baseAccount{}, fmt.Errorf("account type %q is not one this KMS reads", typed.Type)
	}
	return base, nil
}
