# Performance

All numbers below were **measured**, not estimated, on one machine:
Apple M5 Pro (18 cores), macOS, Go 1.26.11, `go test -bench`, loopback
networking, SQLite on the internal SSD. They describe this machine only; run
`make bench` to measure yours. Network latency and Wi-Fi throughput dominate
real-world LAN results.

| Measurement | Result | Benchmark |
|---|---|---|
| Encode a chat envelope (≈260-byte body) | 1.1 µs, 5 allocations | `internal/protocol` `BenchmarkEncodeChat` |
| Decode + validate a chat envelope | 2.6 µs, 1.7 KB allocated | `BenchmarkDecodeChat` |
| Node start (open DB, bind listener, start loops) | 1.3 ms | `tests/integration` `BenchmarkNodeStart` |
| Direct message: send → recipient stores → acknowledgement stored by sender (TLS 1.3, SQLite on both ends) | 0.45 ms per message, sequential | `BenchmarkMessageDelivery` (800 messages) |
| One-way message throughput until all stored by the recipient | ≈ 3,200 messages/s (0.31 ms/message) | `BenchmarkMessageThroughput` (900 messages, within the per-peer burst) |
| File transfer, 64 MiB, SHA-256 on both ends, disk writes | ≈ 650 MB/s | `BenchmarkFileTransfer` |
| Render a 200-message page and draw the screen (120×40) | 2.9 ms | `internal/tui` `BenchmarkRenderConversation/200msgs` |
| Render 2,000 messages | 24 ms | `BenchmarkRenderConversation/2000msgs` |
| `lanchat --version` process | 0.02 s wall, 11 MB max RSS | `/usr/bin/time -l` |
| `lanchat` binary size (darwin/arm64, release flags `-s -w`) | ≈ 21 MB | |

## Deliberate limits that cap throughput

- Each session accepts at most 2,000 envelopes in a burst and 500 per second
  sustained; beyond that the receiver throttles via TCP backpressure.
- Each paired peer may make the receiver store at most 1,000 messages in a
  burst and 50 per second sustained. Messages beyond the quota are not
  acknowledged and are delivered by the sender's normal retry (every 10 s for
  queued messages, after 2 minutes for unacknowledged ones). Human chat never
  reaches these limits; they exist so a misbehaving paired peer cannot fill
  the disk.

## Observations and targets

- Message latency on a LAN is dominated by network round trips (one TLS
  record each way) and two small SQLite transactions; the measured 0.45 ms on
  loopback means local overhead is negligible compared with Wi-Fi latency.
- File throughput on loopback exceeds gigabit Ethernet (≈ 118 MB/s), so
  real transfers are network-bound.
- The UI renders the loaded page of messages (200 at a time, more as you
  scroll up). Rendering grows linearly with loaded messages; a 2,000-message
  view (24 ms) is still below one frame at 30 FPS. Profiling showed text
  wrapping and styling dominate; caching rendered messages is a possible
  future optimisation.
- Discovery latency: with the RFC 6762 query schedule, two instances started
  at the same time on this machine found each other within the first few
  query rounds (under 10 s; the two-process test observed discovery before
  its first check at ~3 s). Peers are dialed immediately after discovery.
