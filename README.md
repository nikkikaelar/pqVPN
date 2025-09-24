# pqVPN — Post‑Quantum Ready VPN (software‑only demo)

pqVPN is a single-file Go demo that sets up a private, software‑only VPN-like tunnel over TCP and exposes a local SOCKS5 proxy on the client. Traffic from your browser/CLI can be pointed at the SOCKS5 proxy and is then encrypted over the tunnel to the server, which connects to the target host/port and relays bytes back and forth.

This demo focuses on plumbing, UX, and performance scaffolding for a hybrid handshake that combines classical X25519 ECDH with a simulated post‑quantum KEM (PQ‑mock). The PQ‑mock mimics message sizes and adds artificial latency to emulate Kyber‑style KEM behavior. It is NOT cryptographically secure and is intended strictly for lab use.

> IMPORTANT: Do not use this in production. PQ‑mock is a placeholder. Replace it with a real PQ KEM (e.g., Kyber via liboqs) before any serious use.

---

## Features

- **Dual modes**: `server` and `client` in a single `main.go`.
- **Hybrid handshake**: Combines X25519 ECDH with a PQ‑mock KEM share. Session keys derived via HKDF.
- **Directional AEAD**: AES‑GCM with independent keys and nonces per direction (client→server, server→client).
- **Local SOCKS5 proxy**: Client starts a SOCKS5 proxy (CONNECT only) so apps can tunnel without TUN/TAP.
- **Zero external deps**: Uses Go stdlib only; easy to run and hack on.

---

## How it works

### 1) Handshake and key derivation
- Client generates an X25519 keypair.
- If `-mode pq-mock`, client also generates a PQ‑mock public/secret (sizes like Kyber512: pk≈800B, ct≈768B, ss=32B) and sends the pk.
- Server generates its X25519 keypair and, if in `pq-mock` mode, encapsulates to the client pk to produce a ciphertext (ct) and a mock shared secret (ss).
- Server replies with its X25519 public key and the PQ‑mock ct (if any).
- Both sides compute X25519 shared secret; client decapsulates the PQ‑mock ct to get the same mock ss. HKDF derives a 32‑byte master session key from `x25519 || pq_ss` (or just `x25519` in classic mode).

### 2) Transport and framing
- From the master key, we derive two AEAD keys via HKDF: one for client→server and one for server→client.
- Each direction uses AES‑GCM with an independent 96‑bit nonce constructed from a 64‑bit counter.
- Application frames are length‑prefixed ciphertext on the wire. Inside the plaintext, simple message types carry control/data.

### 3) Multiplexing and SOCKS5
- The client runs a local SOCKS5 proxy (CONNECT only). When your app connects to the proxy for a host:port, the client opens a logical stream on the VPN link.
- Streams are identified by a small string ID and multiplexed over the single encrypted TCP connection.
- The server receives an Open request for `host:port`, dials it, and then relays data frames in both directions until closed.

---

## Quickstart (Windows / PowerShell)

Prerequisites: Go 1.20+ (tested with Go 1.22).

```powershell
# Clone the repo
git clone https://github.com/nikkikaelar/pqVPN.git
cd pqVPN

# Build (optional)
go build -v

# Terminal A — start server
go run . server -listen :9443

# Terminal B — start client (starts local SOCKS5 127.0.0.1:1080)
go run . client -server 127.0.0.1:9443 -socks 127.0.0.1:1080 -mode pq-mock
```

Configure your browser/CLI to use a SOCKS5 proxy at `127.0.0.1:1080`. Then visit a site or test via:

```powershell
curl --socks5 127.0.0.1:1080 https://example.com
```

### Modes
- `-mode classic`  → X25519 only
- `-mode pq-mock`  → X25519 + PQ‑mock share (latency/plumbing demo)

---

## Command reference

```text
server: go run . server -listen :9443
client: go run . client -server 127.0.0.1:9443 -socks 127.0.0.1:1080 -mode pq-mock
```

Flags:
- `-listen`   (server) bind address, default `:9443`
- `-server`   (client) server address, default `127.0.0.1:9443`
- `-socks`    (client) local SOCKS5 address, default `127.0.0.1:1080`
- `-mode`     handshake mode: `classic` | `pq-mock`

---

## Replacing PQ‑mock with a real PQ KEM

This project isolates the mock behind a tiny `kem` interface so you can swap it out. A real integration (e.g., via liboqs) would resemble:

```go
// Pseudocode API shape
 type RealKEM struct{ /* ... */ }
 func (RealKEM) GenerateKeypair() (pk, sk []byte, err error)
 func (RealKEM) Encapsulate(pk []byte) (ct, ss []byte, err error)
 func (RealKEM) Decapsulate(ct []byte, sk []byte) (ss []byte, err error)
```

Then plug into the handshake path when `-mode pq` is selected.

---

## Security notes (demo‑only)

- PQ‑mock is NOT secure. It only imitates sizes and latency. Do not use for real security.
- Nonce management here uses counters per direction; ensure uniqueness per key if adapted.
- No mutual authentication, no certs, no replay protection. This is a lab demo for tunneling and performance exploration.

---

## Repository layout

- `main.go` — all demo code: handshake, AEAD framing, mux, SOCKS5
- `go.mod` — module definition
- `pqvpn.md` — original design/spec notes
- `.github/workflows/go.yml` — CI build workflow

---

## Roadmap / ideas

- Real PQ integration via liboqs (Kyber512/768) behind the same `kem` interface
- Add tests for handshake, frame encoding, and SOCKS5 flows
- Improve stream management (flow control, backpressure, EOF signaling)
- Optional TLS wrapping on the outer link for identity and NAT traversal
- Observability: structured logs, metrics, and pprof hooks

---

## License

MIT — see `LICENSE`.
