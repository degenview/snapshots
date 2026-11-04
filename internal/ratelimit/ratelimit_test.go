package ratelimit

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestBurstThenRefill(t *testing.T) {
	c := &fakeClock{time.Unix(1000, 0)}
	l := New(6, time.Minute, 3, 100, c.now) // 1 token / 10 s, burst 3
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d refused inside burst", i)
		}
	}
	ok, wait := l.Allow("a")
	if ok {
		t.Fatal("4th request allowed")
	}
	if wait < 9*time.Second || wait > 10*time.Second {
		t.Fatalf("retry after %v, want ~10s", wait)
	}
	c.t = c.t.Add(10 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("token not refilled")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("only one token should have refilled")
	}
	c.t = c.t.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatal("refill must cap at burst, not below it")
		}
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("refill exceeded burst")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	c := &fakeClock{time.Unix(0, 0)}
	l := New(1, time.Hour, 1, 100, c.now)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal()
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal()
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b limited by a")
	}
}

func TestMemoryIsBounded(t *testing.T) {
	c := &fakeClock{time.Unix(0, 0)}
	l := New(1, time.Hour, 1, 50, c.now)
	for i := 0; i < 5000; i++ {
		l.Allow(string(rune('a'+i%26)) + string(rune(i)))
	}
	if l.Len() > 50 {
		t.Fatalf("tracking %d keys, cap is 50", l.Len())
	}
}

func TestIdleBucketsEvictedFirst(t *testing.T) {
	c := &fakeClock{time.Unix(0, 0)}
	l := New(1, time.Second, 1, 2, c.now)
	l.Allow("busy") // empties its bucket
	l.Allow("idle")
	c.t = c.t.Add(1500 * time.Millisecond) // both refilled...
	l.Allow("busy")                        // ...busy spends again
	l.Allow("new")                         // at capacity: idle goes, busy stays
	if ok, _ := l.Allow("busy"); ok {
		t.Fatal("busy lost its state")
	}
}

func TestReconfigure(t *testing.T) {
	c := &fakeClock{time.Unix(0, 0)}
	l := New(1, time.Hour, 1, 10, c.now)
	l.Allow("a")
	l.Reconfigure(1000, time.Second, 5)
	c.t = c.t.Add(time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("new rate not applied")
	}
}

func TestZeroRateReportsLongWait(t *testing.T) {
	l := New(0, time.Hour, 1, 10, nil)
	l.Allow("a")
	if ok, wait := l.Allow("a"); ok || wait <= 0 {
		t.Fatal("zero rate must refuse with a wait")
	}
}

func req(remote string, hdr ...string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	return r
}

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func TestResolver(t *testing.T) {
	proxies := prefixes("10.0.0.0/8", "fd00::/8")
	cases := []struct {
		name    string
		rv      *Resolver
		r       *http.Request
		want    string
		wantErr bool
	}{
		{"no proxies configured ignores header", NewResolver(nil, false, "X-Forwarded-For"), req("203.0.113.5:1234", "X-Forwarded-For", "1.2.3.4"), "203.0.113.5", false},
		{"no header configured ignores header", NewResolver(proxies, false, ""), req("10.1.1.1:80", "X-Forwarded-For", "1.2.3.4"), "10.1.1.1", false},
		{"untrusted peer cannot set header", NewResolver(proxies, false, "X-Forwarded-For"), req("203.0.113.5:1", "X-Forwarded-For", "1.2.3.4"), "203.0.113.5", false},
		{"trusted peer, one hop", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1", "X-Forwarded-For", "198.51.100.7"), "198.51.100.7", false},
		{"client-forged prefix is ignored", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1", "X-Forwarded-For", "6.6.6.6, 198.51.100.7"), "198.51.100.7", false},
		{"two proxy hops", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1", "X-Forwarded-For", "198.51.100.7, 10.0.0.9"), "198.51.100.7", false},
		{"split header lines", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1", "X-Forwarded-For", "6.6.6.6", "X-Forwarded-For", "198.51.100.7"), "198.51.100.7", false},
		{"garbage falls back to peer", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1", "X-Forwarded-For", "not-an-ip"), "10.0.0.2", false},
		{"missing header falls back to peer", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1"), "10.0.0.2", false},
		{"all trusted falls back to peer", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1", "X-Forwarded-For", "10.9.9.9"), "10.0.0.2", false},
		{"single-value header", NewResolver(proxies, false, "cf-connecting-ip"), req("10.0.0.2:1", "CF-Connecting-IP", "198.51.100.9"), "198.51.100.9", false},
		{"ipv4-mapped peer", NewResolver(proxies, false, "X-Forwarded-For"), req("[::ffff:10.0.0.2]:1", "X-Forwarded-For", "198.51.100.7"), "198.51.100.7", false},
		{"ipv6 client", NewResolver(proxies, false, "X-Forwarded-For"), req("10.0.0.2:1", "X-Forwarded-For", "2001:db8::1"), "2001:db8::1", false},
		{"bare peer without port", NewResolver(nil, false, ""), req("192.0.2.1"), "192.0.2.1", false},
		{"zone stripped", NewResolver(nil, false, ""), req("[fe80::1%eth0]:5"), "fe80::1", false},
		{"any peer: header from an unlisted peer", NewResolver(nil, true, "Do-Connecting-IP"), req("172.16.5.5:1", "Do-Connecting-IP", "198.51.100.4"), "198.51.100.4", false},
		{"any peer: takes the last entry", NewResolver(nil, true, "X-Forwarded-For"), req("172.16.5.5:1", "X-Forwarded-For", "6.6.6.6, 198.51.100.4"), "198.51.100.4", false},
		{"any peer: no header falls back", NewResolver(nil, true, "Do-Connecting-IP"), req("172.16.5.5:1"), "172.16.5.5", false},
		{"any peer needs a header", NewResolver(nil, true, ""), req("172.16.5.5:1", "X-Forwarded-For", "1.2.3.4"), "172.16.5.5", false},
		{"unparsable peer", NewResolver(nil, false, ""), req("garbage"), "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.rv.Client(c.r)
			if ok == c.wantErr {
				t.Fatalf("ok = %v", ok)
			}
			if ok && got.String() != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestKeyGroupsIPv6By64(t *testing.T) {
	a := Key(netip.MustParseAddr("2001:db8:1:2::1"))
	b := Key(netip.MustParseAddr("2001:db8:1:2:ffff::9"))
	c := Key(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Fatalf("keys %s %s %s", a, b, c)
	}
	if Key(netip.MustParseAddr("192.0.2.1")) != "192.0.2.1" {
		t.Fatal("ipv4 key changed")
	}
}
