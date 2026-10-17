package protocol

// zeroize overwrites b with zeros. This is a best-effort measure (PROTOCOL.md
// §3.2): the Go runtime may move or copy a slice, so this is not a hard
// guarantee that no copy of the secret remains in memory, but it clears the
// current backing array.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
