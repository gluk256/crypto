package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

type Session struct {
	symKey         []byte
	permPeerHex    []byte
	permPeerKey    *ecdsa.PublicKey
	ephPeerKey     *ecdsa.PublicKey
	incomingMsgCnt uint32
	outgoingMsgCnt uint32
	state          int
}

const (
	debugMode = true

	MinMessageSize   = 256
	MessageTypeIndex = 5

	Invite         = byte(1)
	ACK            = byte(2)
	Reject         = byte(4)
	Quit           = byte(8)
	ProtoThreshold = Quit
	UserThreshold  = TextType
	TextType       = byte(64)
	FileType       = byte(128)
)

const (
	Uninitialized  = 0
	Restarted      = 1
	InviteSent     = 2
	InviteReceived = 4
	AckSent        = 8
	AckReceived    = 16
	Active         = 32
	QuitSent       = 64
	QuitReceived   = 128
	Closed         = 256
)

var (
	socket    net.Conn
	serverIP  string
	sess      Session
	whitelist [][]byte
)

func typeName(t byte) (s string) {
	if t&Invite != 0 {
		s += "Invite "
	}
	if t&ACK != 0 {
		s += "ACK "
	}
	if t&Reject != 0 {
		s += "Reject "
	}
	if t&Quit != 0 {
		s += "Quit "
	}
	if t&TextType != 0 {
		s += "TextType "
	}
	if t&FileType != 0 {
		s += "FileType "
	}
	if len(s) == 0 {
		s = fmt.Sprintf("%d", int(t))
	}
	return s
}

func updateState(t byte) {
	switch t {
	case Invite:
		sess.state |= InviteSent
	case ACK:
		sess.state |= AckSent
	case Quit:
		sess.state |= QuitSent
	}
}

func resetSession() {
	sess.permPeerHex = nil
	sess.permPeerKey = nil
	sess.symKey = nil
	sess.ephPeerKey = nil
	sess.incomingMsgCnt = 0
	sess.outgoingMsgCnt = 0
	sess.state = Restarted
}

func isWhitelisted(p []byte) bool {
	for _, b := range whitelist {
		if bytes.Equal(b, p) {
			return true
		}
	}
	return false
}

func addToWhitelist(p []byte) {
	if !isWhitelisted(p) {
		whitelist = append(whitelist, p)
	}
}

func removeFromWhitelist(p []byte) {
	if len(whitelist) > 0 && len(p) > 0 {
		for i, x := range whitelist {
			if bytes.Equal(x, p) {
				last := len(whitelist) - 1
				whitelist[i] = whitelist[last]
				whitelist = whitelist[:last]
				break
			}
		}
	}
}

func deletePeerFromWhitelist() {
	_, raw, err := common.ImportPubKey()
	if err == nil {
		removeFromWhitelist(raw)
	}
}

func updateLastPeer() {
	if len(sess.permPeerHex) == 0 {
		return
	}

	if len(whitelist) == 0 {
		addToWhitelist(sess.permPeerHex)
		return
	}

	if !isWhitelisted(sess.permPeerHex) {
		addToWhitelist(sess.permPeerHex)
	}

	for i, p := range whitelist {
		if bytes.Equal(p, sess.permPeerHex) {
			if i != 0 {
				whitelist[i] = whitelist[0]
				whitelist[0] = sess.permPeerHex
			}
			return
		}
	}
}

func invitePeerToChatSession(override bool) bool {
	if override {
		resetSession()
	}

	if sess.permPeerKey == nil {
		fmt.Println("Inviting remote peer to the chat session")
		key, raw, err := common.ImportPubKey()
		if err != nil {
			return false
		}
		addToWhitelist(raw)
		sess.permPeerHex = raw
		sess.permPeerKey = key
	}

	err := sendInvite(false)
	if err != nil {
		fmt.Printf("Failed to send ephemeral pub key: %s \n", err.Error())
		return false
	}

	sess.state = Restarted
	updateLastPeer()
	fmt.Printf("Invite sent to remote peer: %x \n", sess.permPeerHex)
	go retryInviteUntilSessionEstablished()
	return true
}

func sendInvite(ack bool) error {
	myEphemeral, err := asym.ExportPubKey(&ephemeralKey.PublicKey)
	if err != nil {
		return err
	}

	sig, err := asym.Sign(clientKey, myEphemeral)
	if err != nil {
		return err
	}

	msg := append(myEphemeral, sig...)
	t := Invite
	newState := InviteSent
	if ack {
		t |= ACK
		newState |= AckSent
	}

	err = sendMessage(msg, t)
	if err == nil {
		sess.state |= newState
	}

	return err
}

func retryInviteUntilSessionEstablished() {
	for i := 0; i < 1000; i++ {
		time.Sleep(1 * time.Second)
		if sess.state >= AckReceived {
			return
		} else {
			err := sendInvite(false)
			if err != nil {
				fmt.Printf("Failed to send invite: %s \n", err.Error())
				return
			}
		}
	}

	fmt.Println("retryInvite failed: timeout")
}

func closeSession(reset bool) {
	err := sendProtocolMessage(Quit)
	if err != nil {
		fmt.Printf("Failed to send quit msg: %s \n", err.Error())
	} else {
		fmt.Println("Session closed")
	}
	if reset {
		time.Sleep(time.Millisecond)
		resetSession()
	}
}

func sendHandshakeToServer() error {
	b := make([]byte, 256)
	crutils.Randomize(b)
	encrypted, err := asym.Encrypt(remoteServerPubKey, b)
	if err == nil {
		err = sendPacket(socket, encrypted)
	}
	return err
}

func runClientMessageLoop() {
	for {
		p, err := receivePacket(socket)
		if err != nil {
			socket.Close()
			return
		}
		go processPacket(p)
	}
}

func isCmd(b []byte) bool {
	s := string(b)
	return s[0] == '\\' || s[0] == '/'
}

func runClientCmdLoop() {
	var err error
	for err == nil {
		s := terminal.PlainTextInput()
		if len(s) != 0 {
			data := s
			t := TextType

			if isCmd(s) {
				if strings.Contains(string(s), "f") {
					t = FileType
					data, err = loadFile()
					if err != nil {
						continue
					}
				} else if strings.Contains(string(s), "w") {
					_, p, err := common.ImportPubKey()
					if err == nil {
						addToWhitelist(p)
					}
					continue
				} else if strings.Contains(string(s), "c") {
					invitePeerToChatSession(false)
					continue
				} else if strings.Contains(string(s), "y") {
					invitePeerToChatSession(false)
					continue
				} else if strings.Contains(string(s), "n") {
					invitePeerToChatSession(true)
					continue
				} else if strings.Contains(string(s), "d") {
					if _, raw, err := common.ImportPubKey(); err == nil {
						removeFromWhitelist(raw)
					}
					continue
				} else if strings.Contains(string(s), "D") {
					removeFromWhitelist(sess.permPeerHex)
					resetSession()
					continue
				} else if strings.Contains(string(s), "p") {
					sess.symKey = common.GetPassword("p")
					continue
				} else if strings.Contains(string(s), "P") {
					sess.symKey = common.GetPassword("s")
					continue
				} else if strings.Contains(string(s), "b") {
					printDiagnosticInfo()
					continue
				} else if strings.Contains(string(s), "h") {
					helpInternal()
					continue
				} else if strings.Contains(string(s), "e") {
					closeSession(false)
					continue
				} else if strings.Contains(string(s), "q") {
					fmt.Println("Quit command received")
					closeSession(true)
					return
				} else {
					continue
				}
			}

			err = sendMessage(data, t)
		}
	}
}

func sendMessage(data []byte, t byte) error {
	p, err := packMessage(data, t)
	if err == nil {
		err = sendPacket(socket, p)
	}
	if err != nil {
		fmt.Printf("Failed to send message: %s \n", err.Error())
	}
	return err
}

func padMessage(p []byte) []byte {
	// todo: data destruction
	// todo: realloc with big capacity
	newSize := getRandMessageSize()
	prevSize := len(p)
	if newSize > prevSize {
		suffix := make([]byte, newSize-prevSize)
		crutils.Randomize(suffix)
		suffix[0] = 0
		p = append(p, suffix...)
	}
	return p
}

func removePadding(p []byte) []byte {
	i := bytes.IndexByte(p, byte(0))
	if i >= 0 {
		p = p[:i]
	}
	return p
}

func packMessage(p []byte, t byte) ([]byte, error) {
	if t != FileType {
		p = padMessage(p)
	}
	// todo: data destruction
	suffix := make([]byte, SuffixSize)
	binary.LittleEndian.PutUint32(suffix, sess.outgoingMsgCnt)
	sess.outgoingMsgCnt++
	suffix[MessageTypeIndex] = t
	p = append(p, suffix...)
	// todo: encryption here
	return p, nil
}

func importPermPeerKey(s string) bool {
	if len(s) != asym.PublicKeySize*2 {
		fmt.Printf("Wrong key length: %d \n", len(s)/2)
		return false
	}
	raw := make([]byte, asym.PublicKeySize)
	n, err := hex.Decode(raw, []byte(s))
	if err != nil {
		fmt.Printf("Failed to import the peer's perm key: %s \n", err.Error())
		return false
	}
	if n != asym.PublicKeySize {
		fmt.Printf("Wrong size of imported key: %d \n", n)
		return false
	}

	key, err := asym.ImportPubKey(raw)
	if err != nil {
		fmt.Println("Failed to import the peer's pub key")
		return false
	}

	addToWhitelist(raw)
	sess.permPeerHex = raw
	sess.permPeerKey = key
	sess.state = Restarted
	return true
}

func loadConnexxionParams(flags string) bool {
	if strings.Contains(flags, "l") {
		serverIP = getDefaultIP()
		remoteServerPubKey = &serverKey.PublicKey
		if len(os.Args) > 2 {
			return importPermPeerKey(os.Args[2])
		}
		return true
	}

	if len(os.Args) > 2 {
		serverIP = os.Args[2]
		if !strings.Contains(serverIP, ":") {
			serverIP += getDefaultPort()
		}
	}

	if len(os.Args) > 3 {
		pub := []byte(os.Args[3])
		if len(pub) != asym.PublicKeySize*2 {
			fmt.Printf("Wrong size of the third param: %d vs. %d \n", len(pub), asym.PublicKeySize*2)
			return false
		}
		k, err := asym.ImportPubKey(pub)
		if err != nil {
			fmt.Println("Failed to import remote server's pub key")
			return false
		}
		remoteServerPubKey = k
	}

	if len(os.Args) > 4 {
		return importPermPeerKey(os.Args[4])
	}

	if len(serverIP) == 0 {
		fmt.Println("Can not connect to remote server: ip is missing")
		return false
	}

	if remoteServerPubKey == nil {
		fmt.Println("Can not connect to remote server: public key is missing")
		return false
	}

	return true
}

func runClient(flags string) {
	common.PrintPublicKey(&clientKey.PublicKey)
	loadPeers(flags) // this func should be called before processing the cmd args
	if !loadConnexxionParams(flags) {
		return
	}
	fmt.Println("xchat v.1 started")
	conn, err := net.Dial("tcp", serverIP)
	if err != nil {
		fmt.Printf("Client error: %s \n", err.Error())
		return
	}
	fmt.Println("connected to server")
	socket = conn

	err = sendHandshakeToServer()
	if err != nil {
		fmt.Printf("Handshake failed: %s \n", err.Error())
	}

	go runClientMessageLoop()

	if strings.Contains(flags, "c") || strings.Contains(flags, "y") {
		if !invitePeerToChatSession(false) {
			return
		}
	}

	runClientCmdLoop()
	shutdown()
}

func shutdown() {
	savePeersList()
	socket.Close()
}

func loadFile() (data []byte, err error) {
	fmt.Println("Sending a file, please enter the file name: ")
	name := terminal.PlainTextInput()
	if len(name) == 0 {
		err = errors.New("empty filename")
		fmt.Printf("Error: %s \n", err.Error())
		return nil, err
	}
	data, err = ioutil.ReadFile(string(name))
	if err != nil {
		fmt.Printf("Error: %s \n", err.Error())
	}
	return data, err
}

func checkNonce(nonce uint32) {
	if nonce != sess.incomingMsgCnt {
		if sess.incomingMsgCnt != 0 {
			fmt.Printf("unexpected msg nonce: [%d vs. %d] \n", nonce, sess.incomingMsgCnt)
		}
		sess.incomingMsgCnt = nonce
	}
	sess.incomingMsgCnt++
}

func parsePacket(p []byte) (raw []byte, t byte, n uint32) {
	sz := len(p)
	if sz < SuffixSize {
		fmt.Println("invalid msg received: too small")
		return raw, t, n
	}
	suffix := p[sz-SuffixSize:]
	raw = p[:sz-SuffixSize]
	t = suffix[MessageTypeIndex]
	n = binary.LittleEndian.Uint32(suffix)
	return raw, t, n
}

func processIncomingInvite(msg []byte) {
	const payloadSize = asym.PublicKeySize + asym.SignatureSize
	if len(msg) < payloadSize {
		fmt.Printf("Invalid Invite received: less than expected size [%d vs %d] \n", len(msg), payloadSize)
		return
	}
	msg = msg[:payloadSize]
	data := msg[:asym.PublicKeySize]
	sig := msg[asym.PublicKeySize:]
	pub, err := asym.SigToPub(data, sig)
	if err != nil {
		fmt.Printf("Error processing EphemeralPub msg: signature recovery failed: %s \n", err.Error())
		return
	}

	if sess.permPeerHex != nil && !bytes.Equal(pub, sess.permPeerHex) {
		sendProtocolMessage(Reject | Quit)
		fmt.Printf("Warning: rejecting invite from unexpected peer: %x \n", pub)
		return
	}

	if sess.permPeerHex == nil && !isWhitelisted(pub) {
		sendProtocolMessage(Reject | Quit)
		fmt.Printf("Warning: rejecting invite from unlisted peer: %x \n", pub)
		fmt.Println("If you trust this key, you should add it to the whitelist (use '\\w' or '\\n' commands)")
		return
	}

	perm, err := asym.ImportPubKey(pub)
	if err != nil {
		fmt.Printf("Error processing EphemeralPub msg: failed to import main key: %s \n", err.Error())
		return
	}
	eph, err := asym.ImportPubKey(data)
	if err != nil {
		fmt.Printf("Error processing EphemeralPub msg: failed to import ephemeral key: %s \n", err.Error())
		return
	}

	sess.permPeerHex = pub
	sess.permPeerKey = perm
	sess.ephPeerKey = eph
	sess.state |= InviteReceived

	if sess.state&InviteSent == 0 {
		err = sendInvite(true)
	} else {
		err = sendProtocolMessage(ACK)
	}
	if err != nil {
		fmt.Printf("Error sending EPH msg: %s \n", err.Error())
		return
	}

	go retryInviteUntilSessionEstablished()
}

func getRandMessageSize() int {
	x := uint64(MinMessageSize)
	r := crutils.PseudorandomUint64() % x
	r += x
	return int(r)
}

func sendProtocolMessage(t byte) error {
	var empty []byte
	err := sendMessage(empty, t)
	if err == nil {
		updateState(t)
	}
	return err
}

func processUserMessage(raw []byte, t byte, nonce uint32) {
	if sess.state < Active {
		sess.state = Active
	}

	if t == FileType {
		h := crutils.Sha2(raw)
		name := fmt.Sprintf("%x", h)
		common.SaveData(name, raw)
		fmt.Printf("[%03d]: saved msg as file %s \n", nonce, name)
	} else if t == TextType {
		raw = removePadding(raw)
		fmt.Printf("[%03d][%s] \n", nonce, string(raw))
	} else {
		fmt.Printf("[%03d]: unknown message type %d \n", nonce, int(t))
	}
}

func processProtocolMessage(raw []byte, t byte, nonce uint32) {
	if debugMode {
		fmt.Printf("[%03d]{msg received: type = %s, size = %d} \n", nonce, typeName(t), len(raw))
	}

	if t > ProtoThreshold {
		fmt.Printf("unknown protocol message type: %d \n", int(t))
	}

	if (t & Invite) != 0 {
		processIncomingInvite(raw)
		sess.state |= InviteReceived
	}

	if (t & ACK) != 0 {
		// todo: check if it was encrypted with my eph key
		sess.state |= AckReceived
	}

	if (t & Reject) != 0 {
		sess.state |= Closed
		fmt.Println("Remote peer rejected your invitation")
	}

	if (t & Quit) != 0 {
		sess.state |= Closed
		fmt.Println("Remote peer closed the session")
	}
}

// todo: add param sig after decryption is implemented (only for protocol msg invite)
// check signature for perm, otherwise it should be encrypted with my eph key
func processMessage(raw []byte, t byte, nonce uint32) {
	if t < UserThreshold {
		processProtocolMessage(raw, t, nonce)
	} else {
		processUserMessage(raw, t, nonce)
	}
}

func processPacket(p []byte) {
	// todo: decrypt
	raw, t, nonce := parsePacket(p)
	if raw != nil {
		checkNonce(nonce)
		processMessage(raw, t, nonce)
	}
}

func printDiagnosticInfo() {
	var eph, perm string
	if sess.permPeerKey != nil {
		perm = "ok"
	}
	if sess.ephPeerKey != nil {
		eph = "ok"
	}
	fmt.Printf("eph: %s, perm: %s, in = %d, out = %d, state = %d \n", eph, perm, sess.incomingMsgCnt, sess.outgoingMsgCnt, sess.state)
}

func getWhitelistFileName() (string, error) {
	name := "peers-"
	pub, err := asym.ExportPubKey(&clientKey.PublicKey)
	if err != nil {
		fmt.Printf("Warning: failed to export client pub key: %s\n", err.Error())
		return name, err
	}

	h := keccak.Digest(pub, 4)
	name += fmt.Sprintf("%x", h)
	return common.GetFullFileName(name), nil
}

func loadPeers(flags string) {
	fullname, err := getWhitelistFileName()
	if err != nil {
		return
	}

	data, err := ioutil.ReadFile(fullname)
	if err != nil {
		fmt.Printf("Warning: failed to load peers list: %s\n", err.Error())
		return
	}

	if len(data) == 0 {
		fmt.Println("Warning: failed to load peers list:file is empty")
		return
	}

	data, _, err = crutils.Decrypt(getFileEncryptionKey(), data)
	if err != nil {
		fmt.Printf("Failed to decrypt whitelist: %s \n", err)
		return
	}

	sz := len(data)
	if sz == 0 {
		fmt.Println("Warning: peers list is empty")
		return
	}

	if sz%asym.PublicKeySize != 0 {
		fmt.Printf("Warning: failed to parse peers list: wrong size %d\n", sz)
		return
	}

	var p []byte
	for i := 0; i < sz; i += asym.PublicKeySize {
		p = data[i : i+asym.PublicKeySize]
		fmt.Printf("Loaded peer: %x \n", p)
		addToWhitelist(p)
	}

	server := p // server key is always the last
	k, err := asym.ImportPubKey(server)
	if err != nil {
		fmt.Printf("Warning: failed to load remote server pub key: %s \n", err.Error())
		return
	}
	remoteServerPubKey = k

	if strings.Contains(flags, "y") {
		if len(whitelist) < 2 { // server key is always present, so we need at least one additional key
			fmt.Println("Warning: failed to restart the previous session: no peer keys loaded")
			return
		}

		key, err := asym.ImportPubKey(whitelist[0])
		if err != nil {
			fmt.Printf("Warning: failed to import the key of previous peer: %s", err.Error())
			return
		}

		sess.permPeerHex = whitelist[0]
		sess.permPeerKey = key
	}

	fmt.Printf("Peers list is loaded: %d entries, including remote server \n", len(whitelist))
}

func savePeersList() {
	var raw []byte
	for _, b := range whitelist {
		raw = append(raw, b...)
	}

	server, err := asym.ExportPubKey(remoteServerPubKey)
	if err != nil {
		fmt.Printf("Failed to export server pub key: %s \n", err)
		server = make([]byte, asym.PublicKeySize)
	}
	raw = append(raw, server...)

	fullName, err := getWhitelistFileName()
	if err != nil {
		return
	}

	raw, err = crutils.Encrypt(getFileEncryptionKey(), raw)
	if err != nil {
		fmt.Printf("Failed to encrypt peers list: %s \n", err)
		return
	}

	err = ioutil.WriteFile(fullName, raw, 0666)
	if err != nil {
		fmt.Printf("Failed to save peers list: %s \n", err)
	}
}
