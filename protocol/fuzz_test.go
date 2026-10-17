package protocol

import "testing"

// Fuzz the wire decoders: the invariant is that no input panics or reads out
// of bounds. These are the hand-rolled byte parsers, so they are the highest-
// value fuzz targets in the library.
func FuzzDecodeHeader(f *testing.F) {
	f.Add(make([]byte, HeaderSize))
	f.Add(make([]byte, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeHeader(b)
	})
}

func FuzzDecodeNormalMessage(f *testing.F) {
	f.Add(make([]byte, NormalMessageHeaderSize+TagSize))
	f.Add([]byte{0x01, 0x02})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeNormalMessage(b)
	})
}

func FuzzDecodeInitialMessage(f *testing.F) {
	f.Add(make([]byte, InitialMessageHeaderSize+TagSize))
	f.Add([]byte{0x01, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeInitialMessage(b)
	})
}

func FuzzDecodeSealedPayload(f *testing.F) {
	f.Add(make([]byte, SealedPayloadPrefixSize))
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeSealedPayload(b)
	})
}

func FuzzDecodeSealedBlob(f *testing.F) {
	f.Add(make([]byte, SealedBlobPrefixSize+TagSize))
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeSealedBlob(b)
	})
}
