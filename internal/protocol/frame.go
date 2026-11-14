// Package protocol implements the versioned LANChat wire protocol.
//
// Every message travels inside a TLS 1.3 session as an explicit frame:
//
//	+----------------+--------+-----------------------+
//	| length uint32  | kind   | payload               |
//	| big endian     | 1 byte | length-1 bytes        |
//	+----------------+--------+-----------------------+
//
// length counts the kind byte and the payload. Kind 1 carries a UTF-8 JSON
// Envelope; kind 2 carries a raw file-transfer chunk. TCP segment boundaries
// are never relied upon. All sizes are bounded before any allocation.
package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Frame size limits.
const (
	// MaxEnvelopeSize bounds a JSON envelope (64 KiB message body plus
	// metadata and JSON escaping overhead).
	MaxEnvelopeSize = 512 * 1024
	// ChunkSize is the maximum file data carried by one chunk frame.
	ChunkSize = 64 * 1024
	// chunkHeader is transfer id (16) + offset (8).
	chunkHeader = 24
	// MaxFrameSize is the absolute upper bound for any frame.
	MaxFrameSize = MaxEnvelopeSize + 1
)

// FrameKind identifies the payload type of a frame.
type FrameKind byte

// Frame kinds.
const (
	KindEnvelope FrameKind = 1
	KindChunk    FrameKind = 2
)

// Errors returned while decoding frames. Any of them is a protocol
// violation and the connection should be closed.
var (
	ErrFrameTooLarge = errors.New("frame exceeds size limit")
	ErrMalformed     = errors.New("malformed frame")
)

// Envelope is the JSON container for every non-chunk message.
//
// The sender of a message is never taken from the envelope: it is the peer
// authenticated by the TLS session the frame arrived on.
type Envelope struct {
	// V is the protocol version the message is encoded with.
	V int `json:"v"`
	// Type selects the body schema, e.g. "chat.message".
	Type string `json:"type"`
	// ID is an optional request identifier (32 lowercase hex characters).
	ID string `json:"id,omitempty"`
	// TS is the sender's wall clock in Unix milliseconds (UTC). It is
	// informational only and never used for security decisions.
	TS int64 `json:"ts,omitempty"`
	// Body is the type-specific payload.
	Body json.RawMessage `json:"body,omitempty"`
}

// Chunk is a decoded file-transfer data frame.
type Chunk struct {
	TransferID string // 32 lowercase hex characters
	Offset     uint64
	Data       []byte
}

// Frame is one decoded frame.
type Frame struct {
	Kind     FrameKind
	Envelope *Envelope
	Chunk    *Chunk
}

// NewEnvelope builds an envelope with a JSON-encoded body.
func NewEnvelope(version int, typ string, body any) (*Envelope, error) {
	env := &Envelope{V: version, Type: typ}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode %s body: %w", typ, err)
		}
		env.Body = b
	}
	return env, nil
}

// EncodeEnvelope serialises env into a complete frame.
func EncodeEnvelope(env *Envelope) ([]byte, error) {
	payload, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: envelope is %d bytes", ErrFrameTooLarge, len(payload))
	}
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(payload)))
	frame[4] = byte(KindEnvelope)
	copy(frame[5:], payload)
	return frame, nil
}

// EncodeChunk serialises a file chunk into a complete frame.
func EncodeChunk(transferID string, offset uint64, data []byte) ([]byte, error) {
	id, err := hex.DecodeString(transferID)
	if err != nil || len(id) != 16 {
		return nil, fmt.Errorf("invalid transfer id %q", transferID)
	}
	if len(data) == 0 || len(data) > ChunkSize {
		return nil, fmt.Errorf("chunk size %d outside 1..%d", len(data), ChunkSize)
	}
	frame := make([]byte, 5+chunkHeader+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+chunkHeader+len(data)))
	frame[4] = byte(KindChunk)
	copy(frame[5:21], id)
	binary.BigEndian.PutUint64(frame[21:29], offset)
	copy(frame[29:], data)
	return frame, nil
}

// Reader decodes frames from a stream.
type Reader struct {
	r *bufio.Reader
}

// NewReader wraps r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 64*1024)}
}

// Next reads the next frame. It returns io.EOF only at a clean frame
// boundary; a truncated frame yields io.ErrUnexpectedEOF.
func (r *Reader) Next() (*Frame, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r.r, hdr[:4]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n == 0 {
		return nil, fmt.Errorf("%w: empty frame", ErrMalformed)
	}
	if n > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	kindByte, err := r.r.ReadByte()
	if err != nil {
		return nil, unexpected(err)
	}
	payloadLen := int(n - 1)
	switch FrameKind(kindByte) {
	case KindEnvelope:
		if payloadLen > MaxEnvelopeSize {
			return nil, fmt.Errorf("%w: envelope %d bytes", ErrFrameTooLarge, payloadLen)
		}
		buf := make([]byte, payloadLen)
		if _, err := io.ReadFull(r.r, buf); err != nil {
			return nil, unexpected(err)
		}
		env, err := DecodeEnvelope(buf)
		if err != nil {
			return nil, err
		}
		return &Frame{Kind: KindEnvelope, Envelope: env}, nil
	case KindChunk:
		if payloadLen <= chunkHeader || payloadLen > chunkHeader+ChunkSize {
			return nil, fmt.Errorf("%w: chunk frame of %d bytes", ErrMalformed, payloadLen)
		}
		buf := make([]byte, payloadLen)
		if _, err := io.ReadFull(r.r, buf); err != nil {
			return nil, unexpected(err)
		}
		return &Frame{Kind: KindChunk, Chunk: &Chunk{
			TransferID: hex.EncodeToString(buf[:16]),
			Offset:     binary.BigEndian.Uint64(buf[16:24]),
			Data:       buf[24:],
		}}, nil
	default:
		return nil, fmt.Errorf("%w: unknown frame kind %d", ErrMalformed, kindByte)
	}
}

// DecodeEnvelope parses and structurally validates a JSON envelope.
func DecodeEnvelope(b []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if env.V < 1 || env.V > 1000 {
		return nil, fmt.Errorf("%w: protocol version %d", ErrMalformed, env.V)
	}
	if env.Type == "" || len(env.Type) > 32 || !isTypeName(env.Type) {
		return nil, fmt.Errorf("%w: message type %q", ErrMalformed, truncate(env.Type, 40))
	}
	if env.ID != "" && !ValidID(env.ID) {
		return nil, fmt.Errorf("%w: envelope id", ErrMalformed)
	}
	return &env, nil
}

func isTypeName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
