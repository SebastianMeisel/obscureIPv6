package main

import "testing"

func testState() State {
	return State{
		Dev:    "enp1s0",
		Prefix: "2a01:04f8:0123:0456",
		PrefixParts: [4]string{
			"2a01", "04f8", "0123", "0456",
		},
	}
}

func TestMatchesPrefixCompressed(t *testing.T) {
	state := testState()

	ip, _, _, _, ok := parseEmbeddedIPv6("2a01:4f8:123:456::1")
	if !ok {
		t.Fatal("expected IPv6 parse to succeed")
	}

	if !MatchesPrefix(ip, state.PrefixParts) {
		t.Fatal("expected compressed address to match prefix")
	}
}

func TestMatchesPrefixExpanded(t *testing.T) {
	state := testState()

	ip, _, _, _, ok := parseEmbeddedIPv6("2a01:04f8:0123:0456:0000:0000:0000:0001")
	if !ok {
		t.Fatal("expected IPv6 parse to succeed")
	}

	if !MatchesPrefix(ip, state.PrefixParts) {
		t.Fatal("expected expanded address to match prefix")
	}
}

func TestDoesNotMatchOtherPrefix(t *testing.T) {
	state := testState()

	ip, _, _, _, ok := parseEmbeddedIPv6("2a01:4f8:999:456::1")
	if !ok {
		t.Fatal("expected IPv6 parse to succeed")
	}

	if MatchesPrefix(ip, state.PrefixParts) {
		t.Fatal("expected non-matching address not to match prefix")
	}
}

func TestRenderObscuredIPv6(t *testing.T) {
	ip, _, _, _, ok := parseEmbeddedIPv6("2a01:4f8:123:456::1")
	if !ok {
		t.Fatal("expected IPv6 parse to succeed")
	}

	got := RenderObscuredIPv6(ip, "", "", false)
	want := "3fff:abc:def:456::1"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestObscureIPv6TextCompressed(t *testing.T) {
	state := testState()

	in := "route to 2a01:4f8:123:456::1 reached"
	got := ObscureIPv6Text(in, state)
	want := "route to 3fff:abc:def:456::1 reached"

	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestObscureIPv6TextExpanded(t *testing.T) {
	state := testState()

	in := "addr 2a01:04f8:0123:0456:0000:0000:0000:0001"
	got := ObscureIPv6Text(in, state)
	want := "addr 3fff:abc:def:456::1"

	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestObscureIPv6TextBracketed(t *testing.T) {
	state := testState()

	in := "connect to [2a01:4f8:123:456::1]"
	got := ObscureIPv6Text(in, state)
	want := "connect to [3fff:abc:def:456::1]"

	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestObscureIPv6TextCIDR(t *testing.T) {
	state := testState()

	in := "prefix 2a01:4f8:123:456::1/64 assigned"
	got := ObscureIPv6Text(in, state)
	want := "prefix 3fff:abc:def:456::1/64 assigned"

	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLeavesUnrelatedIPv6Alone(t *testing.T) {
	state := testState()

	in := "remote 2001:db8::1"
	got := ObscureIPv6Text(in, state)

	if got != in {
		t.Fatalf("got %q, want unchanged %q", got, in)
	}
}

func TestLeavesPlainTextAlone(t *testing.T) {
	state := testState()

	in := "hello world"
	got := ObscureIPv6Text(in, state)

	if got != in {
		t.Fatalf("got %q, want unchanged %q", got, in)
	}
}

func TestObscureIPv6Text(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		s     string
		state State
		want  string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ObscureIPv6Text(tt.s, tt.state)
			// TODO: update the condition below to compare got with tt.want.
			if true {
				t.Errorf("ObscureIPv6Text() = %v, want %v", got, tt.want)
			}
		})
	}
}
