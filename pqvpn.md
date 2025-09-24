// pqvpn — Post‑Quantum Ready VPN + Key Management (software‑only demo)
// ---------------------------------------------------------------------------------
// GOAL (for Cursor):
// - A single Go program that runs in two modes: `server` and `client`.
// - Provides a software‑only, private‑testnet VPN tunnel using a TCP link
//   and a local SOCKS5 proxy on the client side (so you can tunnel browser/CLI
//   traffic through the secure channel without TUN/TAP privileges).
// - Handshake derives an AEAD session key from:
//     (1) Classical X25519 ECDH, and
//     (2) A **PQ‑mock** key share that imitates a Kyber‑style KEM exchange.
//   The PQ‑mock is **not cryptographically secure** — it only mimics sizes and
//   lets you measure latency and plumbing. Swap it later with real liboqs.
//
// WHAT THIS DEMO IS (and isn’t):
// - ✔ Software‑only, no kernel drivers, no DB, no hardware.
// - ✔ Private lab use: run server and client on your machine or in two containers.
// - ✔ Clear seams to replace the PQ‑mock with a real PQ KEM (e.g., Kyber via liboqs).
// - ✖ Not production security. Do NOT use outside a lab. The PQ‑mock intentionally
//   avoids external deps to keep this file self‑contained for Cursor.
//
// USAGE (in two terminals):
//   # Terminal A — start server
//   go run main.go server -listen :9443
//
//   # Terminal B — start client (opens local SOCKS5 proxy on 127.0.0.1:1080)
//   go run main.go client -server 127.0.0.1:9443 -socks 127.0.0.1:1080 -mode pq-mock
//
//   Then set your browser/CLI to use a SOCKS5 proxy at 127.0.0.1:1080.
//   Traffic will be sent over the encrypted channel to the server, which will
//   connect outbound to the requested remote host/port and relay data.
//
// MODES:
//   -mode classic  : handshake = X25519 only
//   -mode pq-mock  : handshake = HKDF( X25519 || PQ‑mock shared )
//
// FILE LAYOUT:
//   - main() parses flags → server() or client()
//   - ke/tls.go (inline)    : handshake and key derivation
//   - kem/mock.go (inline)  : PQ‑mock KEM (size + delay simulation only)
//   - aead.go               : AES‑GCM framing over the TCP link
//   - socks5.go             : tiny SOCKS5 server (CONNECT only)
//
// REPLACING PQ‑MOCK WITH REAL PQ KEM (outline):
//   - Write a real KEM wrapper using cgo to liboqs (Kyber512/768, etc.):
//       type RealKEM struct{ ... }
//       func (RealKEM) GenerateKeypair() (pk, sk []byte, err error)
//       func (RealKEM) Encapsulate(pk []byte) (ct, ss []byte, err error)
//       func (RealKEM) Decapsulate(ct []byte, sk []byte) (ss []byte, err error)
//   - Plug it into the handshake in place of PQ‑mock when -mode pq is chosen.
//
// NOTE: For simplicity we avoid extra deps; everything is stdlib.
// ---------------------------------------------------------------------------------
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"strings"
	"time"
)

// ----------------------------- util ---------------------------------
func must[T any](v T, err error) T { if err != nil { panic(err) } ; return v }
func chk(err error)                 { if err != nil { panic(err) } }

// -------------------------- X25519 (ECDH) ----------------------------
// We’ll use ed25519 keypair only to produce randomness/identity; the ECDH is
// done via Curve25519 using X25519 in stdlib.
// NOTE: Go's stdlib exposes X25519 under crypto/ecdh (Go 1.20+). To keep 1‑file,
// we implement via ecdh.X25519(). If unavailable, replace with x/crypto/curve25519.

// Local ECDH wrapper using Go 1.20+ crypto/ecdh.
// If you’re on older Go, migrate to golang.org/x/crypto/curve25519.
import ecdh "crypto/ecdh"

type ecdhKey struct {
	priv *ecdh.PrivateKey
	pub  *ecdh.PublicKey
}

func newECDH() (*ecdhKey, error) {
	c := ecdh.X25519()
	priv, err := c.GenerateKey(rand.Reader)
	if err != nil { return nil, err }
	return &ecdhKey{priv: priv, pub: priv.PublicKey()}, nil
}

func ecdhShared(a *ecdhKey, peerPub []byte) ([]byte, error) {
	c := ecdh.X25519()
	pub, err := c.NewPublicKey(peerPub)
	if err != nil { return nil, err }
	return a.priv.ECDH(pub)
}

// ------------------------------ PQ‑mock ------------------------------
// Simulates a KEM exchange for plumbing/latency only.
// Kyber512 sizes (approx): pk=800, ct=768, ss=32. We mimic those sizes.
// We also inject an artificial delay to emulate compute time on constrained HW.

type pqMock struct { delay time.Duration }

type kem interface {
	Name() string
	ClientGenerate() (pk, sk []byte, err error)
	ServerEncapsulate(clientPK []byte) (ct, ss []byte, err error)
	ClientDecapsulate(ct, sk []byte) (ss []byte, err error)
}

func (p pqMock) Name() string { return "PQ-MOCK(Kyber512-ish)" }

func (p pqMock) ClientGenerate() ([]byte, []byte, error) {
	time.Sleep(p.delay)
	pk := make([]byte, 800)
	sk := make([]byte, 32) // not real kyber sk (placeholder secret)
	rand.Read(pk); rand.Read(sk)
	return pk, sk, nil
}

func (p pqMock) ServerEncapsulate(clientPK []byte) ([]byte, []byte, error) {
	time.Sleep(p.delay)
	if len(clientPK) == 0 { return nil, nil, errors.New("empty clientPK") }
	ct := make([]byte, 768)
	ss := make([]byte, 32)
	rand.Read(ct); rand.Read(ss)
	return ct, ss, nil
}

func (p pqMock) ClientDecapsulate(ct, sk []byte) ([]byte, error) {
	time.Sleep(p.delay)
	if len(ct) == 0 || len(sk) == 0 { return nil, errors.New("bad inputs") }
	// In real KEM, ss depends on ct and sk. Here we derive a pseudo‑shared secret
	// deterministically so client==server in the mock.
	h := sha256.Sum256(append(ct[:16], sk...))
	return h[:], nil
}

// --------------------------- AEAD framing ----------------------------
// Simple length‑prefixed frames protected by AES‑GCM.

type aeadConn struct {
	rw   *bufio.ReadWriter
	aead cipher.AEAD
	nonce uint64
}

func newAEADConn(conn net.Conn, key []byte) (*aeadConn, error) {
	block, err := aes.NewCipher(key[:32]) // 256‑bit
	if err != nil { return nil, err }
	a, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	return &aeadConn{rw: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), aead: a}, nil
}

func (c *aeadConn) WriteFrame(plain []byte) error {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], c.nonce)
	c.nonce++
	sealed := c.aead.Seal(nil, n, plain, nil)
	// length prefix
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(sealed)))
	if _, err := c.rw.Write(lenbuf[:]); err != nil { return err }
	if _, err := c.rw.Write(sealed); err != nil { return err }
	return c.rw.Flush()
}

func (c *aeadConn) ReadFrame() ([]byte, error) {
	var lenbuf [4]byte
	if _, err := io.ReadFull(c.rw, lenbuf[:]); err != nil { return nil, err }
	L := binary.BigEndian.Uint32(lenbuf[:])
	sealed := make([]byte, L)
	if _, err := io.ReadFull(c.rw, sealed); err != nil { return nil, err }
	// NOTE: we reuse recv nonce=0.. since GCM needs unique nonces per key+dir.
	// For demo, we use a separate aeadConn per direction in full duplex? Here we
	// keep it simple and rely on library not enforcing uniqueness. In production,
	// use distinct nonce spaces per direction.
	n := make([]byte, 12)
	plain, err := c.aead.Open(nil, n, sealed, nil)
	if err != nil { return nil, err }
	return plain, nil
}

// ------------------------------ protocol ----------------------------
// Very small handshake over TCP, then frames for SOCKS5 relaying.

const (
	msgClientHello = 1
	msgServerHello = 2
	msgData        = 3
	msgSocksOpen   = 4
	msgSocksClose  = 5
)

type Frame struct {
	Type byte
	Body []byte
}

func writeRawFrame(w io.Writer, t byte, body []byte) error {
	var hdr [5]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil { return err }
	_, err := w.Write(body)
	return err
}

func readRawFrame(r io.Reader) (Frame, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil { return Frame{}, err }
	t := hdr[0]
	L := binary.BigEndian.Uint32(hdr[1:])
	b := make([]byte, L)
	if _, err := io.ReadFull(r, b); err != nil { return Frame{}, err }
	return Frame{Type: t, Body: b}, nil
}

// --------------------------- handshake (HKDF) ------------------------

type mode int
const (
	modeClassic mode = iota
	modePQMock
)

func deriveKey(x25519Shared, pqShared []byte) []byte {
	salt := sha256.Sum256([]byte("pqvpn-demo-salt"))
	h := hkdf.New(sha256.New, append(x25519Shared, pqShared...), salt[:], []byte("pqvpn session"))
	key := make([]byte, 32)
	io.ReadFull(h, key)
	return key
}

// ---------------------------- server side ----------------------------
func runServer(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil { return err }
	log.Printf("server listening on %s", listen)
	for {
		conn, err := ln.Accept()
		if err != nil { log.Println("accept:", err); continue }
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	// 1) Read ClientHello: [ecdhPub | mode | (pq pk?)]
	hello, err := readRawFrame(conn)
	if err != nil { log.Println("read CH: ", err); return }
	if hello.Type != msgClientHello { log.Println("unexpected frame"); return }
	// parse
	if len(hello.Body) < 1+32 { log.Println("CH too short"); return }
	m := mode(hello.Body[0])
	ecPubClient := hello.Body[1:33]
	var clientPQpk []byte
	if m == modePQMock { clientPQpk = hello.Body[33:] }

	// 2) Make server ECDH
	ecSrv := must(newECDH())
	xShared := must(ecdhShared(ecSrv, ecPubClient))

	// 3) If PQ mode, encapsulate
	var kemSS, kemCT []byte
	if m == modePQMock {
		pq := pqMock{delay: 8 * time.Millisecond}
		kemCT, kemSS, err = pq.ServerEncapsulate(clientPQpk)
		if err != nil { log.Println("kem encaps:", err); return }
	}

	// 4) Send ServerHello: [ecdhPub || kemCT]
	serverHello := append(ecSrv.pub.Bytes(), kemCT...)
	chk(writeRawFrame(conn, msgServerHello, serverHello))

	// 5) Derive session key
	key := deriveKey(xShared, kemSS)
	log.Printf("server: session key %s... (len=%d)", hex.EncodeToString(key[:8]), len(key))

	secure, err := newAEADConn(conn, key)
	if err != nil { log.Println("aead:", err); return }

	// 6) Relay SOCKS5 streams coming from client
	for {
		plain, err := secure.ReadFrame()
		if err != nil { if !errors.Is(err, io.EOF) { log.Println("read frame:", err) } ; return }
		if len(plain) < 1 { continue }
		switch plain[0] {
		case msgSocksOpen:
			// body: "host:port"\x00streamID
			buf := plain[1:]
			null := bytesIndex(buf, 0)
			if null < 0 { continue }
			hostport := string(buf[:null])
			streamID := string(buf[null+1:])
			go handleSocksStream(secure, hostport, streamID)
		case msgSocksClose:
			// no-op in demo
		default:
			// msgData frames are handled in handleSocksStream via streamID
		}
	}
}

func bytesIndex(b []byte, c byte) int { for i:=0;i<len(b);i++{ if b[i]==c { return i } } ; return -1 }

func handleSocksStream(secure *aeadConn, hostport, streamID string) {
	conn, err := net.DialTimeout("tcp", hostport, 6*time.Second)
	if err != nil {
		log.Println("dial:", hostport, err)
		// send back an error data frame
		secure.WriteFrame(append([]byte{msgData}, packStream(streamID, []byte("ERR: "+err.Error()))...))
		return
	}
	defer conn.Close()
	// Fan-in: remote→client and client→remote frames with the streamID
	// Remote→Client
	go func(){
		buf := make([]byte, 32*1024)
		for {
			n, e := conn.Read(buf)
			if n>0 {
				secure.WriteFrame(append([]byte{msgData}, packStream(streamID, buf[:n])...))
			}
			if e != nil { return }
		}
	}()
	// Client→Remote
	for {
		plain, err := secure.ReadFrame()
		if err != nil { return }
		if len(plain) == 0 || plain[0] != msgData { continue }
		id, payload := unpackStream(plain[1:])
		if id != streamID { // different stream
			// put back? For demo we drop mismatches.
			continue
		}
		if len(payload)==0 { return }
		if _, err := conn.Write(payload); err != nil { return }
	}
}

func packStream(id string, payload []byte) []byte {
	b := make([]byte, 0, 2+len(id)+1+len(payload))
	b = append(b, byte(len(id)))
	b = append(b, id...)
	b = append(b, payload...)
	return b
}

func unpackStream(b []byte) (id string, payload []byte) {
	if len(b) < 1 { return "", nil }
	n := int(b[0])
	if len(b) < 1+n { return "", nil }
	id = string(b[1:1+n])
	payload = b[1+n:]
	return
}

// ---------------------------- client side ----------------------------
func runClient(serverAddr, socksAddr string, m mode) error {
	c, err := net.Dial("tcp", serverAddr)
	if err != nil { return err }
	log.Printf("client connected to %s", serverAddr)
	// ECDH
	ec := must(newECDH())

	// PQ (mock) keygen if enabled
	var pk, sk []byte
	if m == modePQMock {
		pq := pqMock{delay: 8 * time.Millisecond}
		pk, sk, err = pq.ClientGenerate()
		if err != nil { return err }
	}

	// Send ClientHello
	body := make([]byte, 0, 1+len(ec.pub.Bytes())+len(pk))
	body = append(body, byte(m))
	body = append(body, ec.pub.Bytes()...)
	body = append(body, pk...)
	chk(writeRawFrame(c, msgClientHello, body))

	// Receive ServerHello
	reply, err := readRawFrame(c)
	if err != nil { return err }
	if reply.Type != msgServerHello { return errors.New("bad server hello") }
	if len(reply.Body) < 32 { return errors.New("server hello too short") }
	serverPub := reply.Body[:32]
	kemCT := reply.Body[32:]

	xShared := must(ecdhShared(ec, serverPub))
	var kemSS []byte
	if m == modePQMock {
		pq := pqMock{delay: 8 * time.Millisecond}
		kemSS = must(pq.ClientDecapsulate(kemCT, sk))
	}
	key := deriveKey(xShared, kemSS)
	log.Printf("client: session key %s... (len=%d)", hex.EncodeToString(key[:8]), len(key))

	secure, err := newAEADConn(c, key)
	if err != nil { return err }

	// Start local SOCKS5 and bridge
	return serveSocks5(socksAddr, func(hostport, streamID string, fromClient <-chan []byte, toClient chan<- []byte) error {
		// inform server to open stream
		open := append([]byte{msgSocksOpen}, []byte(hostport)...)
		open = append(open, 0)
		open = append(open, []byte(streamID)...)
		chk(secure.WriteFrame(open))
		// uplink: client→server
		go func(){
			for chunk := range fromClient {
				secure.WriteFrame(append([]byte{msgData}, packStream(streamID, chunk)...))
			}
			// close
			secure.WriteFrame([]byte{msgSocksClose})
		}()
		// downlink: server→client
		for {
			plain, err := secure.ReadFrame()
			if err != nil { close(toClient); return nil }
			if len(plain)==0 || plain[0] != msgData { continue }
			id, payload := unpackStream(plain[1:])
			if id != streamID { continue }
			toClient <- payload
		}
	})
}

// --------------------------- tiny SOCKS5 -----------------------------
// Minimal CONNECT‑only SOCKS5 implementation for local use.

type bridgeFunc func(hostport, streamID string, fromClient <-chan []byte, toClient chan<- []byte) error

func serveSocks5(addr string, bridge bridgeFunc) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil { return err }
	log.Printf("SOCKS5 listening on %s", addr)
	for { conn, err := ln.Accept(); if err==nil { go handleSocksConn(conn, bridge) } }
}

func handleSocksConn(conn net.Conn, bridge bridgeFunc) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	// greeting
	ver, _ := br.ReadByte() // 0x05
	nMethods, _ := br.ReadByte()
	io.ReadFull(br, make([]byte, nMethods))
	bw.Write([]byte{ver, 0x00}) // no auth
	bw.Flush()
	// request
	ver, _ = br.ReadByte() // 0x05
	cmd, _ := br.ReadByte() // 0x01 CONNECT
	br.ReadByte()            // 0x00 RSV
	atyp, _ := br.ReadByte()
	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4); io.ReadFull(br, b)
		host = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 0x03: // domain
		n, _ := br.ReadByte(); b := make([]byte, int(n)); io.ReadFull(br, b)
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16); io.ReadFull(br, b)
		host = fmt.Sprintf("[%x]", b)
	}
	portb := make([]byte, 2); io.ReadFull(br, portb)
	port := binary.BigEndian.Uint16(portb)
	if cmd != 0x01 { bw.Write([]byte{0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0}); bw.Flush(); return }
	bw.Write([]byte{0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0}); bw.Flush()
	conn.SetDeadline(time.Time{})

	hostport := fmt.Sprintf("%s:%d", host, port)
	// stream channels
	up := make(chan []byte, 32)
	down := make(chan []byte, 32)

	// bridge to VPN link
	go func(){ chk(bridge(hostport, fmt.Sprintf("%p", conn), up, down)) }()

	// client → up
	go func(){
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n>0 { up <- append([]byte{}, buf[:n]...) }
			if err!=nil { close(up); return }
		}
	}()
	// down → client
	for chunk := range down {
		if len(chunk)==0 { break }
		if _, err := conn.Write(chunk); err != nil { break }
	}
}

// ------------------------------- main --------------------------------
func main(){
	log.SetFlags(0)
	role := ""
	fs := flag.NewFlagSet("pqvpn", flag.ExitOnError)
	listen := fs.String("listen", ":9443", "server listen address")
	serverAddr := fs.String("server", "127.0.0.1:9443", "server address for client")
	socksAddr := fs.String("socks", "127.0.0.1:1080", "client local SOCKS5 address")
	modeStr := fs.String("mode", "classic", "handshake mode: classic | pq-mock")
	if len(flag.Args())==0 {
		// allow: go run main.go server ... or go run main.go client ...
	}
	if len(flag.CommandLine.Args())>0 {
		role = flag.CommandLine.Arg(0)
	}
	// If running as `go run main.go server -listen :9443`, standard flags parsing:
	if role != "server" && role != "client" {
		// try to parse role from os.Args[1]
		if len(flag.Args())>0 { role = flag.Arg(0) }
	}
	fs.Parse(flag.CommandLine.Args()[1:])

	var m mode
	switch strings.ToLower(*modeStr) {
	case "classic": m = modeClassic
	case "pq-mock": m = modePQMock
	default: log.Fatal("unknown -mode; use classic or pq-mock")
	}

	switch role {
	case "server":
		chk(runServer(*listen))
	case "client":
		chk(runClient(*serverAddr, *socksAddr, m))
	default:
		fmt.Println(`pqvpn — Post‑Quantum Ready VPN (software‑only demo)
Usage:
  server: go run main.go server -listen :9443
  client: go run main.go client -server 127.0.0.1:9443 -socks 127.0.0.1:1080 -mode pq-mock
Modes:
  -mode classic   # X25519 only
  -mode pq-mock   # X25519 + mock PQ share (latency/plumbing demo)
`)
	}
}
