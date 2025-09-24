// pqvpn — Post‑Quantum Ready VPN + Key Management (software‑only demo)
// ---------------------------------------------------------------------------------
// GOAL:
// - A single Go program that runs in two modes: `server` and `client`.
// - Provides a software‑only, private‑testnet VPN tunnel using a TCP link
//   and a local SOCKS5 proxy on the client side (no TUN/TAP required).
// - Handshake derives an AEAD session from:
//     (1) Classical X25519 ECDH, and
//     (2) A PQ‑mock key share that imitates a Kyber‑style KEM exchange.
//   The PQ‑mock is NOT cryptographically secure — it only mimics sizes and
//   lets you measure latency and plumbing. Swap later with real liboqs.
// ---------------------------------------------------------------------------------
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	ecdh "crypto/ecdh"
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
	"net"
	"strings"
	"sync"
	"time"
)

// ----------------------------- util ---------------------------------
func must[T any](v T, err error) T { if err != nil { panic(err) }; return v }
func chk(err error)               { if err != nil { panic(err) } }

// -------------------------- X25519 (ECDH) ----------------------------
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
// Simulates a KEM exchange for plumbing/latency only (Kyber512-ish sizes).

type pqMock struct { delay time.Duration }

type kem interface {
	Name() string
	ClientGenerate() (pk, sk []byte, err error)
	ServerEncapsulate(clientPK []byte) (ct, ss []byte, err error)
	ClientDecapsulate(ct []byte, sk []byte) (ss []byte, err error)
}

func (p pqMock) Name() string { return "PQ-MOCK(Kyber512-ish)" }

func (p pqMock) ClientGenerate() ([]byte, []byte, error) {
	time.Sleep(p.delay)
	pk := make([]byte, 800)
	sk := make([]byte, 32)
	_, _ = rand.Read(pk)
	_, _ = rand.Read(sk)
	return pk, sk, nil
}

func (p pqMock) ServerEncapsulate(clientPK []byte) ([]byte, []byte, error) {
	time.Sleep(p.delay)
	if len(clientPK) == 0 { return nil, nil, errors.New("empty clientPK") }
	ct := make([]byte, 768)
	ss := make([]byte, 32)
	_, _ = rand.Read(ct)
	_, _ = rand.Read(ss)
	return ct, ss, nil
}

func (p pqMock) ClientDecapsulate(ct, sk []byte) ([]byte, error) {
	time.Sleep(p.delay)
	if len(ct) == 0 || len(sk) == 0 { return nil, errors.New("bad inputs") }
	h := sha256.Sum256(append(ct[:16], sk...))
	return h[:], nil
}

// --------------------------- AEAD framing ----------------------------
// We derive two independent AEAD keys (c->s and s->c) from a master key.
// Each direction maintains its own nonce counter.

type secureConn struct {
	rw        *bufio.ReadWriter
	sendAEAD  cipher.AEAD
	recvAEAD  cipher.AEAD
	sendCtr   uint64
	recvCtr   uint64
	writeLock sync.Mutex
}

func hkdfExpand(master []byte, info string, n int) []byte {
	salt := sha256.Sum256([]byte("pqvpn-aead-salt"))
	h := hkdf.New(sha256.New, master, salt[:], []byte(info))
	out := make([]byte, n)
	io.ReadFull(h, out)
	return out
}

func newSecureConn(conn net.Conn, master []byte, isServer bool) (*secureConn, error) {
	// Derive directional keys
	c2sKey := hkdfExpand(master, "key c->s", 32)
	s2cKey := hkdfExpand(master, "key s->c", 32)
	var sendKey, recvKey []byte
	if isServer {
		recvKey = c2sKey
		sendKey = s2cKey
	} else {
		sendKey = c2sKey
		recvKey = s2cKey
	}
	b1, err := aes.NewCipher(sendKey)
	if err != nil { return nil, err }
	a1, err := cipher.NewGCM(b1)
	if err != nil { return nil, err }
	b2, err := aes.NewCipher(recvKey)
	if err != nil { return nil, err }
	a2, err := cipher.NewGCM(b2)
	if err != nil { return nil, err }
	return &secureConn{rw: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), sendAEAD: a1, recvAEAD: a2}, nil
}

func (s *secureConn) writeCiphertext(ct []byte) error {
	// length prefix (u32)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(ct)))
	if _, err := s.rw.Write(lb[:]); err != nil { return err }
	if _, err := s.rw.Write(ct); err != nil { return err }
	return s.rw.Flush()
}

func (s *secureConn) readCiphertext() ([]byte, error) {
	var lb [4]byte
	if _, err := io.ReadFull(s.rw, lb[:]); err != nil { return nil, err }
	L := binary.BigEndian.Uint32(lb[:])
	buf := make([]byte, L)
	if _, err := io.ReadFull(s.rw, buf); err != nil { return nil, err }
	return buf, nil
}

func (s *secureConn) WritePlain(plain []byte) error {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], s.sendCtr)
	s.sendCtr++
	ct := s.sendAEAD.Seal(nil, n, plain, nil)
	return s.writeCiphertext(ct)
}

func (s *secureConn) ReadPlain() ([]byte, error) {
	ct, err := s.readCiphertext()
	if err != nil { return nil, err }
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], s.recvCtr)
	plain, err := s.recvAEAD.Open(nil, n, ct, nil)
	if err != nil { return nil, err }
	s.recvCtr++
	return plain, nil
}

// ------------------------------ protocol ----------------------------
const (
	msgClientHello byte = 1
	msgServerHello byte = 2
	msgOpen        byte = 3 // open stream: hostport\x00streamID
	msgData        byte = 4 // data: [len(id):1][id][payload]
	msgClose       byte = 5 // close: [len(id):1][id]
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

func deriveMaster(x25519Shared, pqShared []byte) []byte {
	salt := sha256.Sum256([]byte("pqvpn-demo-salt"))
	h := hkdf.New(sha256.New, append(x25519Shared, pqShared...), salt[:], []byte("pqvpn session"))
	key := make([]byte, 32)
	io.ReadFull(h, key)
	return key
}

// ------------------------------ mux ---------------------------------
// A simple per-connection dispatcher so only one goroutine reads from the link.

type streamManager struct {
	incoming map[string]chan []byte
	mu       sync.Mutex
}

func newStreamManager() *streamManager {
	return &streamManager{incoming: make(map[string]chan []byte)}
}

func (m *streamManager) ensure(id string) chan []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.incoming[id]
	if !ok {
		ch = make(chan []byte, 32)
		m.incoming[id] = ch
	}
	return ch
}

func (m *streamManager) remove(id string) {
	m.mu.Lock()
	if ch, ok := m.incoming[id]; ok { close(ch); delete(m.incoming, id) }
	m.mu.Unlock()
}

func packData(id string, payload []byte) []byte {
	b := make([]byte, 0, 1+len(id)+len(payload))
	b = append(b, byte(len(id)))
	b = append(b, id...)
	b = append(b, payload...)
	return b
}

func unpackData(b []byte) (id string, payload []byte) {
	if len(b) < 1 { return "", nil }
	n := int(b[0])
	if len(b) < 1+n { return "", nil }
	id = string(b[1 : 1+n])
	payload = b[1+n:]
	return
}

// ---------------------------- server side ----------------------------
func runServer(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil { return err }
	log.Printf("server listening on %s", listen)
	for {
		conn, err := ln.Accept()
		if err != nil { log.Println("accept:", err); continue }
		go handleServerConn(conn)
	}
}

func handleServerConn(conn net.Conn) {
	defer conn.Close()
	// 1) Read ClientHello: [mode:1 | ecPub:32 | (pq pk?)]
	hello, err := readRawFrame(conn)
	if err != nil { log.Println("read CH:", err); return }
	if hello.Type != msgClientHello || len(hello.Body) < 1+32 { log.Println("bad CH"); return }
	m := mode(hello.Body[0])
	ecPubClient := hello.Body[1:33]
	var clientPQpk []byte
	if m == modePQMock { clientPQpk = hello.Body[33:] }

	// 2) Make server ECDH
	ecSrv := must(newECDH())
	xShared := must(ecdhShared(ecSrv, ecPubClient))

	// 3) PQ encapsulate if used
	var kemSS, kemCT []byte
	if m == modePQMock {
		pq := pqMock{delay: 8 * time.Millisecond}
		kemCT, kemSS, err = pq.ServerEncapsulate(clientPQpk)
		if err != nil { log.Println("kem encaps:", err); return }
	}

	// 4) Send ServerHello: [ecPub:32 || kemCT]
	serverHello := append(ecSrv.pub.Bytes(), kemCT...)
	chk(writeRawFrame(conn, msgServerHello, serverHello))

	// 5) Derive master and secure link
	master := deriveMaster(xShared, kemSS)
	log.Printf("server: session key %s...", hex.EncodeToString(master[:8]))
	link := must(newSecureConn(conn, master, true))

	// 6) Stream dispatcher and loop
	mgr := newStreamManager()
	go serverReaderLoop(link, mgr)

	// Keep the connection alive; readerLoop handles streams as they arrive
	select {}
}

func serverReaderLoop(link *secureConn, mgr *streamManager) {
	for {
		plain, err := link.ReadPlain()
		if err != nil { if !errors.Is(err, io.EOF) { log.Println("server read:", err) }; return }
		if len(plain) == 0 { continue }
		switch plain[0] {
		case msgOpen:
			body := plain[1:]
			// body: hostport\x00streamID
			i := bytesIndex(body, 0)
			if i < 0 { continue }
			hostport := string(body[:i])
			streamID := string(body[i+1:])
			ch := mgr.ensure(streamID)
			go handleSocksStreamServer(link, mgr, ch, hostport, streamID)
		case msgData:
			id, payload := unpackData(plain[1:])
			mgr.ensure(id) <- append([]byte{}, payload...)
		case msgClose:
			id, _ := unpackData(plain[1:])
			mgr.remove(id)
		}
	}
}

func handleSocksStreamServer(link *secureConn, mgr *streamManager, fromClient <-chan []byte, hostport, streamID string) {
	remote, err := net.DialTimeout("tcp", hostport, 6*time.Second)
	if err != nil {
		log.Println("dial:", hostport, err)
		_ = link.WritePlain(append([]byte{msgData}, packData(streamID, []byte("ERR: "+err.Error()))...))
		mgr.remove(streamID)
		return
	}
	defer remote.Close()

	// Remote -> Client
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, e := remote.Read(buf)
			if n > 0 {
				_ = link.WritePlain(append([]byte{msgData}, packData(streamID, buf[:n])...))
			}
			if e != nil { _ = link.WritePlain(append([]byte{msgClose}, packData(streamID, nil)...)); mgr.remove(streamID); return }
		}
	}()

	// Client -> Remote
	for chunk := range fromClient {
		if len(chunk) == 0 { break }
		if _, err := remote.Write(chunk); err != nil { break }
	}
	_ = link.WritePlain(append([]byte{msgClose}, packData(streamID, nil)...))
	mgr.remove(streamID)
}

func bytesIndex(b []byte, c byte) int { for i:=0;i<len(b);i++ { if b[i]==c { return i } } ; return -1 }

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
	if reply.Type != msgServerHello || len(reply.Body) < 32 { return errors.New("bad server hello") }
	serverPub := reply.Body[:32]
	kemCT := reply.Body[32:]

	xShared := must(ecdhShared(ec, serverPub))
	var kemSS []byte
	if m == modePQMock {
		pq := pqMock{delay: 8 * time.Millisecond}
		kemSS = must(pq.ClientDecapsulate(kemCT, sk))
	}
	master := deriveMaster(xShared, kemSS)
	log.Printf("client: session key %s...", hex.EncodeToString(master[:8]))
	link := must(newSecureConn(c, master, false))

	mgr := newStreamManager()
	go clientReaderLoop(link, mgr)

	// Start local SOCKS5 and bridge
	return serveSocks5(socksAddr, func(hostport, streamID string, fromClient <-chan []byte, toClient chan<- []byte) error {
		// Register channel for downstream data
		ch := mgr.ensure(streamID)
		// Inform server to open stream
		open := append([]byte{msgOpen}, []byte(hostport)...)
		open = append(open, 0)
		open = append(open, []byte(streamID)...)
		chk(link.WritePlain(open))
		// uplink: client->server
		go func() {
			for chunk := range fromClient {
				_ = link.WritePlain(append([]byte{msgData}, packData(streamID, chunk)...))
			}
			_ = link.WritePlain(append([]byte{msgClose}, packData(streamID, nil)...))
		}()
		// downlink: server->client
		for {
			payload, ok := <-ch
			if !ok { close(toClient); mgr.remove(streamID); return nil }
			if len(payload) == 0 { close(toClient); mgr.remove(streamID); return nil }
			toClient <- payload
		}
	})
}

func clientReaderLoop(link *secureConn, mgr *streamManager) {
	for {
		plain, err := link.ReadPlain()
		if err != nil { if !errors.Is(err, io.EOF) { log.Println("client read:", err) }; return }
		if len(plain) == 0 { continue }
		switch plain[0] {
		case msgData:
			id, payload := unpackData(plain[1:])
			mgr.ensure(id) <- append([]byte{}, payload...)
		case msgClose:
			id, _ := unpackData(plain[1:])
			mgr.remove(id)
		}
	}
}

// --------------------------- tiny SOCKS5 -----------------------------
// Minimal CONNECT‑only SOCKS5 implementation for local use.

type bridgeFunc func(hostport, streamID string, fromClient <-chan []byte, toClient chan<- []byte) error

func serveSocks5(addr string, bridge bridgeFunc) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil { return err }
	log.Printf("SOCKS5 listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err == nil { go handleSocksConn(conn, bridge) }
	}
}

func handleSocksConn(conn net.Conn, bridge bridgeFunc) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
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
	br.ReadByte()           // 0x00 RSV
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
	_ = conn.SetDeadline(time.Time{})

	hostport := fmt.Sprintf("%s:%d", host, port)
	// stream channels
	up := make(chan []byte, 32)
	down := make(chan []byte, 32)

	// bridge to VPN link
	go func() { _ = bridge(hostport, fmt.Sprintf("%p", conn), up, down) }()

	// client -> up
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 { up <- append([]byte{}, buf[:n]...) }
			if err != nil { close(up); return }
		}
	}()
	// down -> client
	for chunk := range down {
		if len(chunk) == 0 { break }
		if _, err := conn.Write(chunk); err != nil { break }
	}
}

// ------------------------------- main --------------------------------
func main() {
	log.SetFlags(0)
	if len(flag.Args()) == 0 {
		// allow role as first arg like: go run . server ...
	}

	fs := flag.NewFlagSet("pqvpn", flag.ExitOnError)
	listen := fs.String("listen", ":9443", "server listen address")
	serverAddr := fs.String("server", "127.0.0.1:9443", "server address for client")
	socksAddr := fs.String("socks", "127.0.0.1:1080", "client local SOCKS5 address")
	modeStr := fs.String("mode", "classic", "handshake mode: classic | pq-mock")

	role := ""
	if len(flag.CommandLine.Args()) > 0 { role = flag.CommandLine.Arg(0) }
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
  server: go run . server -listen :9443
  client: go run . client -server 127.0.0.1:9443 -socks 127.0.0.1:1080 -mode pq-mock
Modes:
  -mode classic   # X25519 only
  -mode pq-mock   # X25519 + mock PQ share (latency/plumbing demo)
`)
	}
}
