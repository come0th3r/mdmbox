package control

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

// Copied explicitly into the pinned sing checkout for compatibility testing.
// Uses synthetic cached interfaces; no proxy, TUN or route changes are made.
func TestMDMBOXCachedInterfaceLookup(t *testing.T) {
	finder := NewDefaultInterfaceFinder()
	finder.UpdateInterfaces([]Interface{{
		Index: 4242, Name: "mdmbox-synthetic", MTU: 1500,
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")},
	}})
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		got, err := finder.InterfaceByAddr(netip.MustParseAddr(address))
		if err != nil || got == nil || got.Index != 4242 || got.Name != "mdmbox-synthetic" {
			t.Fatalf("cached address lookup: got=%v err=%v", got, err)
		}
	}
	if index, err := finder.InterfaceIndexByName("mdmbox-synthetic"); err != nil || index != 4242 {
		t.Fatalf("cached name lookup: index=%d err=%v", index, err)
	}
	if name, err := finder.InterfaceNameByIndex(4242); err != nil || name != "mdmbox-synthetic" {
		t.Fatalf("cached index lookup: name=%q err=%v", name, err)
	}
}

func TestMDMBOXMissingInterfaceError(t *testing.T) {
	// An IPv4 / IPv6 interface prefix cannot contain an IPv4-mapped IPv6
	// address through netip.Prefix.Contains, making this a deterministic miss.
	address := netip.MustParseAddr("::ffff:192.0.2.1")
	finder := NewDefaultInterfaceFinder()
	got, err := finder.InterfaceByAddr(address)
	if got != nil || err == nil {
		t.Fatalf("expected missing-interface error, got=%v err=%v", got, err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected *net.OpError, got %T", err)
	}
	if opErr.Op != "route" || opErr.Net != "ip+net" || opErr.Err.Error() != "no such network interface" {
		t.Fatalf("unexpected error shape: %v", opErr)
	}
	if ipAddr, ok := opErr.Addr.(*net.IPAddr); !ok || !ipAddr.IP.Equal(net.IP(address.AsSlice())) {
		t.Fatalf("unexpected error address: %v", opErr.Addr)
	}
}
