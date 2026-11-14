package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func BenchmarkEncodeChat(b *testing.B) {
	msg := ChatMessage{MessageID: NewID(), Kind: ConvRoom, Room: "general", Body: strings.Repeat("hello world ", 20), SentAt: 1}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		env, err := NewEnvelope(1, TypeChat, msg)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := EncodeEnvelope(env); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeChat(b *testing.B) {
	msg := ChatMessage{MessageID: NewID(), Kind: ConvRoom, Room: "general", Body: strings.Repeat("hello world ", 20), SentAt: 1}
	env, _ := NewEnvelope(1, TypeChat, msg)
	frame, _ := EncodeEnvelope(env)
	// One reader per session, as in production: frames are read back to back.
	stream := bytes.Repeat(frame, b.N)
	r := NewReader(bytes.NewReader(stream))
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f, err := r.Next()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeBody[ChatMessage](f.Envelope); err != nil {
			b.Fatal(err)
		}
	}
}
