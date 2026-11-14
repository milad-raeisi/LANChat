# Security model

This document describes what LANChat protects, against whom, how, and where
its limits are. It reflects the implementation in this repository.

## Assets and goals

- **Confidentiality and integrity** of messages and files between paired
  peers.
- **Authenticity**: a message attributed to Maryam was sent by the key you
  paired with as Maryam.
- **No unauthorised trust**: nobody becomes trusted without explicit approval
  by the local user.
- **Local safety**: nothing received can execute code, write outside the
  download directory, or manipulate the terminal.
- **Availability within limits**: malformed or excessive traffic must not
  crash or freeze the application or grow storage without bound.
- **Privacy**: no telemetry, no internet use, history stored only locally.

## Threat model

Considered attackers:

1. Anyone on the local network who can send mDNS packets and open TCP/TLS
   connections with any number of self-generated identities.
2. An active man-in-the-middle on the LAN (ARP/mDNS spoofing).
3. A peer that was legitimately paired and later turns malicious.

Out of scope: a compromised local computer or user account (malware can read
the database and key), physical access, and denial of service by flooding the
network itself.

## Identity

- Each installation generates an Ed25519 key once (`crypto/rand`). The peer ID
  and fingerprint are hashes of the public key (see
  [protocol.md](protocol.md)); they cannot be claimed by another key.
- Storage: PKCS#8 in a PEM file with permissions 0600 inside a 0700 directory
  on macOS/Linux; on Windows additionally encrypted with DPAPI for the current
  user account. Platform keychain integration (macOS Keychain, Secret Service)
  is not implemented.
- The key is never logged or printed. `lanchat identity reset` replaces it
  after explicit confirmation; peers then see a new identity and must pair
  again.

## Transport

- TLS 1.3 with mutual authentication for every connection; there is no
  unencrypted mode and the configuration rejects attempts to disable it.
- Certificates are self-signed by the identity key. LANChat verifies the key,
  not a certificate chain or validity period, so no clock synchronisation is
  needed.
- A dialer that expects a particular peer (from discovery) aborts if a
  different identity answers and records an identity-mismatch warning.

## Trust and pairing

- Discovery results (mDNS, static peers, managed server) are hints. A
  discovered or connected peer is **unpaired** and can only exchange
  `hello`, `presence`, pings and pairing messages.
- Pairing uses commit-then-reveal nonces bound into a six-digit verification
  code (exact construction in [protocol.md](protocol.md#pairing-exchange)).
  Both users compare the code out of band and approve. Trust is stored only
  when both sides approved on the same TLS session.
  - A passive or active man-in-the-middle terminates two TLS sessions with
    different keys and exporters. The commitment prevents it from choosing its
    nonces after seeing the honest side's, so it cannot make the two codes
    match except by chance (1 in 10⁶ per attempt), and each attempt is a new
    pairing request the users see.
  - An unsolicited `pair.accept`, or one on a different session, is ignored.
  - In the UI, pairing and file-offer dialogs default to "Later", have no
    single-key accept, and ignore input for 800 ms after opening, so typing
    or a stray Enter cannot approve a request.
- **Impersonation warnings**: a new identity using the same display and device
  name as a paired peer is flagged; a paired peer renaming itself to someone
  else's name raises a warning; message senders whose name collides with
  another person (or with your own name, or imitates "(you)") are shown with
  their short peer ID. Display names are never treated as identity.
- **Revocation** (`/unpair`, `lanchat peers revoke`) stops message exchange in
  both directions from your side, fails queued messages to that peer and
  informs the peer.

## Authorisation of messages

- Chat, group and file messages are accepted only from paired peers, and the
  sender is always the TLS-authenticated peer.
- Direct messages are only ever sent to the addressed peer. Room messages are
  sent only to paired peers who announced the room; group messages only to
  members of the local snapshot, and accepted only from members.
- Group IDs are bound to the owner's key; snapshots are accepted only from the
  owner with increasing versions.
- Acknowledgements and file-control messages only affect state belonging to
  the peer that sent them.
- Replay: TLS prevents replay on the network; inside a session, duplicates are
  suppressed by (sender, message ID). Transfer IDs and group versions reject
  stale or repeated control messages.

## Local safety

- **Terminal output**: every string from the network (names, messages, file
  names, error texts, room and group names) is sanitised before rendering:
  escape and control characters, C1 controls, bidirectional overrides and
  invisible format characters are removed; stacked combining marks are capped;
  blank look-alike characters are removed from names; text is wrapped by
  display width. Message bodies are indented so they cannot imitate interface
  lines. Text exports are sanitised the same way.
- **Commands** typed in the UI are local actions; no command or message ever
  causes a shell command to run.
- **Files**: received files go only to the download directory under a
  sanitised single-component name; they are written to a 0600 temporary file,
  verified (size and SHA-256) and only then renamed without overwriting. They
  are never opened or executed; on macOS they carry the quarantine attribute
  and on Windows the Mark-of-the-Web, so the system warns before opening.
- **SQL**: all queries are parameterised.
- **Logging**: logs go to a file, never the terminal; message bodies and keys
  are not logged (sensitive attribute names are redacted defensively).

## Resource limits

Frame sizes are bounded before allocation; inbound message rate per session
is throttled with TCP backpressure; per-peer quotas bound stored messages,
group updates and file offers; never-paired identities are kept in memory only
(at most 256) and never written to disk; dials, handshakes (also per source
IP), sessions, unpaired sessions and transfers are capped; stalled transfers
time out. Details: [architecture.md](architecture.md).

## Security properties per mode

| Mode | What is protected | What others can observe |
|---|---|---|
| mDNS (default) | message content and files (TLS between the two devices); identities | on the LAN: your display name, device name, peer ID, IP address and port (mDNS); who connects to whom and when, and traffic volume |
| Static peers | same | the listed hosts see connection attempts |
| Managed discovery | same; the server never receives messages or files | the server operator sees which authorised identities are online, their names and addresses; other authorised peers see the directory |

**Encryption in transit is not end-to-end storage encryption**: messages are
decrypted on each participant's device and stored in plain SQLite there.
There is no relaying, so no intermediate party sees plaintext. Group and room
messages are encrypted separately on each pairwise session.

## Known limitations

- History and keys at rest are protected by operating-system permissions only
  (plus DPAPI for the key on Windows). Use full-disk encryption.
- Pairing relies on users actually comparing the code.
- mDNS announcements reveal presence and names to everyone on the segment.
- A paired peer can send unpleasant but bounded content; revoke it if needed.
- Membership changes of a group depend on its owner being online.
- No forward secrecy beyond what TLS 1.3 provides per session; no
  post-compromise security for stored data.

## Verification

Security-relevant behaviour is covered by tests: TLS rejection of missing,
non-Ed25519 and forged certificates; identity mismatch; spoofed hello IDs;
unsolicited trust; commitment mismatch; one-sided approval; group-ID hijack;
untrusted messages and invitations; malformed frames (plus fuzzing of the
frame reader and text sanitiser); terminal-escape neutralisation in the UI;
dialog input guards; path traversal and reserved file names. An independent
adversarial review was carried out on this codebase and its findings were
fixed (see `CHANGELOG.md`). Report vulnerabilities as described in
[SECURITY.md](../SECURITY.md).
