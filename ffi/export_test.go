package main

import "testing"

// TestCopyInRejectsNegativeLength guards against the process-fatal panic a
// negative caller-supplied length would otherwise cause (C3).
func TestCopyInRejectsNegativeLength(t *testing.T) {
	if b, ok := copyIn(nil, -1); ok || b != nil {
		t.Fatal("copyIn(nil, -1) should return nil, false")
	}
	if b, ok := copyIn(nil, 0); !ok || b != nil {
		t.Fatal("copyIn(nil, 0) should return nil, true")
	}
	if b, ok := copyIn(nil, 1); ok || b != nil {
		t.Fatal("copyIn(nil, 1) should return nil, false (nil pointer)")
	}
}
