package integration_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// BenchmarkNodeStart measures opening the database, binding the listener
// and starting the background loops of a node (with an existing identity).
func BenchmarkNodeStart(b *testing.B) {
	home := b.TempDir()
	n := startNode(b, "Warm", home)
	n.stop()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := startNode(b, "Bench", home)
		b.StopTimer()
		n.stop()
		b.StartTimer()
	}
}

// BenchmarkMessageDelivery measures the time from SendText until the
// recipient's acknowledgement has been stored by the sender (one direct
// message over loopback TLS, sequentially).
func BenchmarkMessageDelivery(b *testing.B) {
	a := startNode(b, "A", "")
	c := startNode(b, "B", "")
	pair(b, a, c)
	dm, _ := a.OpenDirect(context.Background(), c.ID())
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m, err := a.SendText(ctx, dm, "benchmark message "+strconv.Itoa(i))
		if err != nil {
			b.Fatal(err)
		}
		for {
			got, err := a.store.GetMessage(ctx, m.Seq)
			if err == nil && got.Delivery.Delivered == 1 {
				break
			}
			time.Sleep(50 * time.Microsecond)
		}
	}
}

// BenchmarkMessageThroughput measures sustained one-way throughput: b.N
// messages are sent back to back and the clock stops when the recipient
// has stored all of them.
func BenchmarkMessageThroughput(b *testing.B) {
	a := startNode(b, "A", "")
	c := startNode(b, "B", "")
	pair(b, a, c)
	dm, _ := a.OpenDirect(context.Background(), c.ID())
	back := storage.DirectConversationID(a.ID())
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.SendText(ctx, dm, "m"+strconv.Itoa(i)); err != nil {
			b.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Minute)
	for {
		c2, err := c.store.GetConversation(ctx, back)
		if err == nil && c2.Unread >= b.N {
			break
		}
		if time.Now().After(deadline) {
			b.Fatalf("only %d of %d messages arrived", c2.Unread, b.N)
		}
		time.Sleep(time.Millisecond)
	}
}

// BenchmarkFileTransfer measures throughput of a 64 MiB transfer over
// loopback, including SHA-256 on both ends and the disk writes.
func BenchmarkFileTransfer(b *testing.B) {
	const size = 64 << 20
	a := startNode(b, "A", "")
	c := startNode(b, "B", "")
	pair(b, a, c)
	src := filepath.Join(b.TempDir(), "payload.bin")
	data := make([]byte, size)
	_, _ = rand.Read(data)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id, err := a.SendFile(context.Background(), c.ID(), src)
		if err != nil {
			b.Fatal(err)
		}
		eventually(b, "offer", 10*time.Second, func() bool {
			for _, t := range c.Transfers() {
				if t.ID == id {
					return true
				}
			}
			return false
		})
		if err := c.RespondFile(context.Background(), id, true); err != nil {
			b.Fatal(err)
		}
		eventually(b, "transfer", 2*time.Minute, func() bool {
			for _, t := range a.Transfers() {
				if t.ID == id {
					return t.State == node.TransferCompleted
				}
			}
			return false
		})
	}
}
