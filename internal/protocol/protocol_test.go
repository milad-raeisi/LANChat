package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

func mustEnvelope(t *testing.T, typ string, body any) []byte {
	t.Helper()
	env, err := NewEnvelope(1, typ, body)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestEnvelopeRoundTrip(t *testing.T) {
	msg := ChatMessage{MessageID: NewID(), Kind: ConvRoom, Room: "general", Body: "Hello everyone! 👋", SentAt: 1763116200000}
	var buf bytes.Buffer
	buf.Write(mustEnvelope(t, TypeChat, msg))
	buf.Write(mustEnvelope(t, TypePing, Ping{Nonce: NewID()}))
	r := NewReader(&buf)
	f, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindEnvelope || f.Envelope.Type != TypeChat {
		t.Fatalf("unexpected frame %+v", f)
	}
	got, err := DecodeBody[ChatMessage](f.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if *got != msg {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, msg)
	}
	if f, err = r.Next(); err != nil || f.Envelope.Type != TypePing {
		t.Fatalf("second frame: %v %v", f, err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestChunkRoundTrip(t *testing.T) {
	id := NewID()
	data := bytes.Repeat([]byte{0xAB}, ChunkSize)
	frame, err := EncodeChunk(id, 1<<40, data)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewReader(bytes.NewReader(frame)).Next()
	if err != nil {
		t.Fatal(err)
	}
	if f.Chunk.TransferID != id || f.Chunk.Offset != 1<<40 || !bytes.Equal(f.Chunk.Data, data) {
		t.Fatal("chunk mismatch")
	}
	if _, err := EncodeChunk(id, 0, make([]byte, ChunkSize+1)); err == nil {
		t.Fatal("oversized chunk accepted")
	}
	if _, err := EncodeChunk("zz", 0, []byte{1}); err == nil {
		t.Fatal("bad transfer id accepted")
	}
}

func frameWithLen(n uint32, kind byte, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(b, n)
	b[4] = kind
	copy(b[5:], payload)
	return b
}

func TestReaderRejectsBadFrames(t *testing.T) {
	cases := map[string][]byte{
		"zero length":    {0, 0, 0, 0},
		"too large":      frameWithLen(MaxFrameSize+1, 1, nil),
		"unknown kind":   frameWithLen(2, 9, []byte{0}),
		"bad json":       frameWithLen(4, 1, []byte("{x}")),
		"short chunk":    frameWithLen(5, 2, []byte{1, 2, 3, 4}),
		"no version":     frameWithLen(uint32(1+len(`{"type":"ping"}`)), 1, []byte(`{"type":"ping"}`)),
		"bad type chars": frameWithLen(uint32(1+len(`{"v":1,"type":"PING!"}`)), 1, []byte(`{"v":1,"type":"PING!"}`)),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewReader(bytes.NewReader(b)).Next()
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrFrameTooLarge) {
				t.Fatalf("expected protocol error, got %v", err)
			}
		})
	}
	// Truncated frame: header promises more bytes than are available.
	_, err := NewReader(bytes.NewReader(frameWithLen(100, 1, []byte("{}")))).Next()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestOversizedEnvelopeNotEncoded(t *testing.T) {
	env := &Envelope{V: 1, Type: TypeChat, Body: json.RawMessage(`"` + strings.Repeat("a", MaxEnvelopeSize) + `"`)}
	if _, err := EncodeEnvelope(env); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestValidation(t *testing.T) {
	peer, _ := identity.Generate()
	pid := string(peer.ID())
	good := []Validator{
		&Hello{ProtocolVersion: 1, MinVersion: 1, PeerID: pid, DisplayName: "Milad", ListenPort: 47777},
		&ChatMessage{MessageID: NewID(), Kind: ConvDirect, Body: "hi"},
		&ChatMessage{MessageID: NewID(), Kind: ConvGroup, GroupID: NewID(), Body: "hi"},
		&Presence{DisplayName: "A", Status: "online", Rooms: []string{"general", "dev-team"}},
		&GroupUpdate{GroupID: NewID(), Salt: NewID(), Name: "Team", OwnerID: pid, Version: 1, State: GroupActive, Members: []GroupMember{{PeerID: pid, DisplayName: "A"}}},
		&PairRequest{DisplayName: "A", Commit: strings.Repeat("ab", 32)},
		&PairNonce{Nonce: strings.Repeat("01", 32)},
		&FileOffer{TransferID: NewID(), Name: "report.pdf", Size: 10},
		&FileDone{TransferID: NewID(), Size: 10, SHA256: strings.Repeat("ab", 32)},
		&Ack{MessageID: NewID(), Status: AckDelivered},
	}
	for _, v := range good {
		if err := v.Validate(); err != nil {
			t.Errorf("%T should validate: %v", v, err)
		}
	}
	bad := []Validator{
		&Hello{ProtocolVersion: 1, MinVersion: 2, PeerID: pid, DisplayName: "x"},
		&Hello{ProtocolVersion: 1, MinVersion: 1, PeerID: "not-an-id", DisplayName: "x"},
		&ChatMessage{MessageID: "short", Kind: ConvRoom, Room: "general", Body: "hi"},
		&ChatMessage{MessageID: NewID(), Kind: ConvRoom, Room: "../etc", Body: "hi"},
		&ChatMessage{MessageID: NewID(), Kind: ConvDirect, Body: "   "},
		&ChatMessage{MessageID: NewID(), Kind: ConvDirect, Body: strings.Repeat("x", MaxBodyBytes+1)},
		&ChatMessage{MessageID: NewID(), Kind: ConvDirect, Body: "bad \xff utf8"},
		&ChatMessage{MessageID: NewID(), Kind: "broadcast", Body: "hi"},
		&Presence{DisplayName: "A", Status: "online", Rooms: []string{"UPPER"}},
		&GroupUpdate{GroupID: NewID(), Salt: NewID(), Name: "Team", OwnerID: pid, Version: 1, State: GroupActive},
		&GroupUpdate{GroupID: NewID(), Name: "Team", OwnerID: pid, Version: 1, State: GroupActive, Members: []GroupMember{{PeerID: pid}}},
		&PairRequest{DisplayName: "A", Commit: "short"},
		&PairNonce{Nonce: strings.Repeat("AB", 32)},
		&GroupUpdate{GroupID: NewID(), Salt: NewID(), Name: "Team", OwnerID: pid, Version: 0, State: GroupActive, Members: []GroupMember{{PeerID: pid}}},
		&FileOffer{TransferID: NewID(), Name: "x", Size: -1},
		&FileDone{TransferID: NewID(), SHA256: "nothex"},
		&Ack{MessageID: NewID(), Status: "read"},
	}
	for _, v := range bad {
		if err := v.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%T %+v should be rejected, got %v", v, v, err)
		}
	}
}

func TestNegotiate(t *testing.T) {
	if v, ok := Negotiate(1, 3, 2, 5); !ok || v != 3 {
		t.Fatalf("got %d %v", v, ok)
	}
	if _, ok := Negotiate(1, 1, 2, 2); ok {
		t.Fatal("incompatible ranges negotiated")
	}
}

func TestRoomNames(t *testing.T) {
	for _, ok := range []string{"general", "dev", "team-1", "a_b", "9lives"} {
		if !ValidRoomName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-x", "General", "a b", "x/y", strings.Repeat("a", 33), "日本"} {
		if ValidRoomName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
	if NormalizeRoomName("  #Dev ") != "dev" {
		t.Fatal("normalize")
	}
}

func FuzzReader(f *testing.F) {
	seed, _ := EncodeEnvelope(&Envelope{V: 1, Type: TypePing, Body: json.RawMessage(`{"nonce":"00112233445566778899aabbccddeeff"}`)})
	f.Add(seed)
	chunk, _ := EncodeChunk(NewID(), 0, []byte("data"))
	f.Add(chunk)
	f.Add([]byte{0, 0, 0, 1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bytes.NewReader(data))
		for i := 0; i < 16; i++ {
			fr, err := r.Next()
			if err != nil {
				return
			}
			if fr.Kind == KindEnvelope {
				// Body decoding of arbitrary input must never panic.
				_, _ = DecodeBody[ChatMessage](fr.Envelope)
				_, _ = DecodeBody[Hello](fr.Envelope)
				_, _ = DecodeBody[GroupUpdate](fr.Envelope)
				_, _ = DecodeBody[FileOffer](fr.Envelope)
			}
		}
	})
}

func FuzzChatBody(f *testing.F) {
	f.Add(`{"message_id":"00112233445566778899aabbccddeeff","kind":"room","room":"general","body":"hi","sent_at":1}`)
	f.Add(`{"kind":"direct","body":"\u001b[2J"}`)
	f.Fuzz(func(t *testing.T, body string) {
		env := &Envelope{V: 1, Type: TypeChat, Body: json.RawMessage(body)}
		m, err := DecodeBody[ChatMessage](env)
		if err == nil && (len(m.Body) > MaxBodyBytes || !ValidID(m.MessageID)) {
			t.Fatalf("invalid message accepted: %+v", m)
		}
	})
}
