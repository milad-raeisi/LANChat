package tui

import (
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/milad-raeisi/LANChat/internal/storage"
)

// BenchmarkRenderConversation measures re-rendering a full page (200
// messages, the page size) and a large 2,000-message history plus drawing
// the screen.
func BenchmarkRenderConversation(b *testing.B) {
	for _, n := range []int{pageSize, 2000} {
		b.Run(strconv.Itoa(n)+"msgs", func(b *testing.B) {
			f := newFake(&testing.T{})
			m := NewModel(f, nil)
			m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
			start := time.Now().Add(-time.Duration(n) * time.Minute)
			for i := 0; i < n; i++ {
				m.msgs = append(m.msgs, storage.Message{
					Seq: int64(i + 1), ConversationID: storage.GeneralRoomID, SenderID: identityID(strconv.Itoa(i % 7)),
					SenderName: "User " + strconv.Itoa(i%7), Kind: storage.MessageText,
					Body: strings.Repeat("Some chat text with emoji 👋 and wrapping. ", 1+i%5), SentAt: start.Add(time.Duration(i) * time.Minute),
				})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.renderMessages()
				_ = m.View()
			}
		})
	}
}
