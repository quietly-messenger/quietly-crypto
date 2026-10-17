package protocol

// zeroizeFn is an opaque call target so the compiler cannot prove the stores
// below are dead and eliminate them. zeroize routes through it as cheap
// insurance that the wipe actually executes (Go issue #19057 territory).
var zeroizeFn = func(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroize overwrites b with zeros. This is a best-effort measure (PROTOCOL.md
// §3.2): the Go runtime may move or copy a slice, so this is not a hard
// guarantee that no copy of the secret remains in memory, but it clears the
// current backing array.
func zeroize(b []byte) {
	zeroizeFn(b)
}
