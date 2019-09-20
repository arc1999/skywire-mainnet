package network

import (
	"context"
	"errors"
	"net"
	"sync"
)

var (
	// ErrNoSuchNetworker is being returned when there's no suitable networker.
	ErrNoSuchNetworker = errors.New("no such networker")
	// ErrNetworkerAlreadyExists is being returned when there's already one with such Network type.
	ErrNetworkerAlreadyExists = errors.New("networker already exists")
)

var (
	networkers   = map[Type]Networker{}
	networkersMx sync.RWMutex
)

// AddNetworker associated Networker with the `network`.
func AddNetworker(t Type, n Networker) error {
	networkersMx.Lock()
	defer networkersMx.Unlock()

	if _, ok := networkers[t]; ok {
		return ErrNetworkerAlreadyExists
	}

	networkers[t] = n

	return nil
}

// ResolveNetworker resolves Networker by `network`.
func ResolveNetworker(t Type) (Networker, error) {
	networkersMx.RLock()
	n, ok := networkers[t]
	if !ok {
		networkersMx.RUnlock()
		return nil, ErrNoSuchNetworker
	}
	networkersMx.RUnlock()
	return n, nil
}

// Networker defines basic network operations, such as Dial/Listen.
type Networker interface {
	Dial(addr Addr) (net.Conn, error)
	DialContext(ctx context.Context, addr Addr) (net.Conn, error)
	Listen(addr Addr) (net.Listener, error)
	ListenContext(ctx context.Context, addr Addr) (net.Listener, error)
}

// Dial dials the remote `addr` of the specified `network`.
func Dial(t Type, addr Addr) (net.Conn, error) {
	return DialContext(context.Background(), t, addr)
}

// DialContext dials the remote `Addr` of the specified `network` with the context.
func DialContext(ctx context.Context, t Type, addr Addr) (net.Conn, error) {
	n, err := ResolveNetworker(t)
	if err != nil {
		return nil, err
	}

	return n.DialContext(ctx, addr)
}

// Listen starts listening on the local `addr` of the specified `network`.
func Listen(t Type, addr Addr) (net.Listener, error) {
	return ListenContext(context.Background(), t, addr)
}

// ListenContext starts listening on the local `addr` of the specified `network` with the context.
func ListenContext(ctx context.Context, t Type, addr Addr) (net.Listener, error) {
	networker, err := ResolveNetworker(t)
	if err != nil {
		return nil, err
	}

	return networker.ListenContext(ctx, addr)
}
