package opstate

import (
	"context"
	"errors"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdSource is the Source over an etcd client (the member on this server, through its unix socket).
type EtcdSource struct {
	client *clientv3.Client
}

// NewEtcdSource wraps a client the caller made and closes.
func NewEtcdSource(client *clientv3.Client) (*EtcdSource, error) {
	if client == nil {
		return nil, errors.New("opstate: no etcd client")
	}
	return &EtcdSource{client: client}, nil
}

// List is a linearizable read of the prefix: the revision it returns is the store's, as of a moment the
// majority agreed on.
func (s *EtcdSource) List(ctx context.Context, prefix string) (map[string][]byte, uint64, int64, error) {
	response, err := s.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, 0, 0, err
	}
	if response.More {
		return nil, 0, 0, errors.New("the store answered with a partial list")
	}
	values := make(map[string][]byte, len(response.Kvs))
	for _, kv := range response.Kvs {
		values[string(kv.Key)] = kv.Value
	}
	return values, response.Header.ClusterId, response.Header.Revision, nil
}

// Watch streams the prefix's changes from fromRevision on, with progress notifications.
func (s *EtcdSource) Watch(ctx context.Context, prefix string, fromRevision int64) <-chan Update {
	out := make(chan Update)
	// RequireLeader: a member cut off from the majority ends the stream instead of going quiet.
	watch := s.client.Watch(clientv3.WithRequireLeader(ctx), prefix, clientv3.WithPrefix(), clientv3.WithRev(fromRevision),
		clientv3.WithProgressNotify())
	go func() {
		defer close(out)
		for response := range watch {
			update := Update{ClusterID: response.Header.ClusterId, Revision: response.Header.Revision, Progress: response.IsProgressNotify()}
			switch {
			case response.CompactRevision != 0:
				update.Compacted = true
			case response.Canceled || response.Err() != nil:
				update.Err = fmt.Errorf("%v", response.Err())
			}
			for _, event := range response.Events {
				update.Changes = append(update.Changes, Change{Key: string(event.Kv.Key), Value: event.Kv.Value,
					Deleted: event.Type == clientv3.EventTypeDelete, ModRevision: event.Kv.ModRevision})
			}
			select {
			case out <- update:
			case <-ctx.Done():
				return
			}
			if update.Err != nil || update.Compacted {
				return
			}
		}
	}()
	return out
}

// RequestProgress asks for a progress notification on this client's watch streams.
func (s *EtcdSource) RequestProgress(ctx context.Context) error {
	return s.client.RequestProgress(clientv3.WithRequireLeader(ctx))
}
