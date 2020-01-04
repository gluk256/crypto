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

	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

type Session struct {
	permPeerHex    []byte
	permPeerKey    *ecdsa.PublicKey
	ephPeerKey     *ecdsa.PublicKey
	incomingMsgCnt uint32
	outgoingMsgCnt uint32
	state          int
}

const (
	debugMode = true

	MinMessageSize   = 256 // todo: use it for padding the text (review the actual size)
	MessageTypeIndex = 5

	Invite   = byte(1)
	ACK      = byte(2)
	Quit     = byte(4)
	QuitAck  = byte(8)
	TextType = byte(64)
	FileType = byte(128)

	ProtoThreshold = QuitAck
	UserThreshold  = TextType
)

const (
	Uninitialized    = 0
	Restarted        = 1
	InviteSent       = 2
	InviteReceived   = 4
	AckSent          = 8
	AckReceived      = 16
	Active           = 32
	QuitSent         = 64
	QuitReceived     = 128
	QuitAckSent      = 256
	QuitAckReceived  = 512
	UnexpectedClosed = 1024
	GracefullyClosed = 2048
)

var (
	socket    net.Conn
	serverIP  string
	sess      Session
	whiteList [][]byte
)

func typeName(t byte) string {
	switch t {
	case Invite:
		return "Invite"
	case ACK:
		return "ACK"
	case Quit:
		return "Quit"
	case QuitAck:
		return "QuitAck"
	case TextType:
		return "TextType"
	case FileType:
		return "FileType"
	default:
		return "unknown"
	}
}

func updateState(t byte) {
	switch t {
	case Invite:
		sess.state |= InviteSent
	case ACK:
		sess.state |= AckSent
	case Quit:
		sess.state |= QuitSent
	case QuitAck:
		sess.state |= QuitAckSent
	}
}

func resetSession() {
	sess.permPeerHex = nil
	sess.permPeerKey = nil
	sess.ephPeerKey = nil
	sess.incomingMsgCnt = 0
	sess.outgoingMsgCnt = 0
	sess.state = Restarted
}

func isListed(arr [][]byte, pub []byte) bool {
	for _, b := range arr {
		if bytes.Equal(b, pub) {
			return true
		}
	}
	return false
}

func removeFromList(arr [][]byte, p []byte) {
	if len(arr) > 0 && len(p) > 0 {
		for i, x := range arr {
			if bytes.Equal(x, p) {
				last := len(arr) - 1
				arr[i] = arr[last]
				arr = arr[:last]
				break
			}
		}
	}
}

func invitePeerToChatSession(override bool) bool {
	if override {
		resetSession()
	}

	if sess.permPeerKey == nil {
		key, raw, err := common.ImportPubKey()
		if err != nil {
			return false
		}
		whiteList = append(whiteList, raw)
		sess.permPeerKey = key
		sess.permPeerHex = raw
		sess.state = Restarted
	}

	err := sendInvite(false)
	if err != nil {
		fmt.Printf("Failed to send ephemeral pub key: %s \n", err.Error())
		return false
	}

	fmt.Println("New session successfully initiated")
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
		time.Sleep(1 * time.Second) // todo: review
		if (sess.state&InviteReceived) == 0 || (sess.state&AckReceived) == 0 {
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

func closeSession() {
	err := sendRandomMessage(Quit)
	if err != nil {
		fmt.Printf("Failed to send quit msg: %s \n", err.Error())
		return
	}

	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		if (sess.state & QuitReceived) == 0 {
			err := sendRandomMessage(Quit)
			if err != nil {
				fmt.Printf("Failed to send quit msg: %s \n", err.Error())
				return
			}
		} else {
			return
		}
	}

	fmt.Println("Session did not close gracefully: timeout")
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
	for err == nil && sess.state < UnexpectedClosed {
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
						whiteList = append(whiteList, p)
					}
					continue
				} else if strings.Contains(string(s), "c") {
					invitePeerToChatSession(false)
					continue
				} else if strings.Contains(string(s), "n") {
					invitePeerToChatSession(true)
					continue
				} else if strings.Contains(string(s), "d") {
					// todo: delete peer
					continue
				} else if strings.Contains(string(s), "D") {
					removeFromList(whiteList, sess.permPeerHex)
					resetSession()
					continue
				} else if strings.Contains(string(s), "o") {
					printDiagnosticInfo()
					continue
				} else if strings.Contains(string(s), "h") {
					helpInternal()
					continue
				} else if strings.Contains(string(s), "q") {
					closeSession()
					break
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

func packMessage(p []byte, msgType byte) ([]byte, error) {
	if msgType == TextType {
		p = padMessage(p)
	}
	// todo: data destruction
	suffix := make([]byte, SuffixSize)
	sess.outgoingMsgCnt++
	binary.LittleEndian.PutUint32(suffix, sess.outgoingMsgCnt)
	suffix[MessageTypeIndex] = msgType
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

	k, err := asym.ImportPubKey(raw)
	if err != nil {
		fmt.Println("Failed to import the peer's pub key")
		return false
	}

	whiteList = append(whiteList, raw)
	sess.permPeerKey = k
	sess.permPeerHex = raw
	sess.state = Restarted
	return true
}

func loadConnexxionParams(flags string) bool {
	if strings.Contains(flags, "l") {
		serverIP = getDefaultIP()
		remoteServerPubKey = &serverKey.PublicKey
		if len(os.Args) > 3 {
			return importPermPeerKey(os.Args[3])
		}
	} else if len(os.Args) < 4 {
		fmt.Println("Can not connect to the server: not enough parameters")
		return false
	} else {
		serverIP = os.Args[2]
		if !strings.Contains(serverIP, ":") {
			serverIP += getDefaultPort()
		}
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
		if len(os.Args) > 5 {
			return importPermPeerKey(os.Args[5])
		}
	}
	return true
}

func runClient(flags string) {
	common.PrintPublicKey(&clientKey.PublicKey)
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

	if sess.permPeerKey != nil || strings.Contains(flags, "c") {
		if !invitePeerToChatSession(false) {
			return
		}
	}

	runClientCmdLoop()
	conn.Close()
}

func loadFile() ([]byte, error) {
	fmt.Println("Sending a file, please enter the file name: ")
	name := terminal.PlainTextInput()
	if len(name) == 0 {
		info := string("empty filename")
		fmt.Printf("Error: %s \n", info)
		return nil, errors.New(info)
	}
	data, err := ioutil.ReadFile(string(name))
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

func processIncomingEphemeralPub(msg []byte) {
	const expectedSize = asym.PublicKeySize + asym.SignatureSize
	if len(msg) != expectedSize {
		fmt.Printf("Invalid EphemeralPub msg received: wrong size [%d vs %d] \n", len(msg), expectedSize)
		return
	}

	data := msg[:asym.PublicKeySize]
	sig := msg[asym.PublicKeySize:]
	pub, err := asym.SigToPub(data, sig)
	if err != nil {
		fmt.Printf("Error processing EphemeralPub msg: signature recovery failed: %s \n", err.Error())
		return
	}

	if sess.permPeerHex != nil && !bytes.Equal(pub, sess.permPeerHex) {
		fmt.Printf("Warning: rejecting invite from unexpected peer: %s \n", pub)
		return
	}

	if sess.permPeerHex == nil && !isListed(whiteList, pub) {
		fmt.Printf("Warning: rejecting invite from unlisted peer: %s \n", pub)
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

	err = sendInvite(true)
	if err != nil {
		fmt.Printf("Error sending EPH msg: %s \n", err.Error())
		return
	}

	fmt.Println("New session initiated by remote peer")
	go retryInviteUntilSessionEstablished()
}

func getRandMessageSize() (r int) {
	r = MinMessageSize
	r += int(crutils.PseudorandomUint64()) % MinMessageSize
	return r
}

func sendRandomMessage(t byte) error {
	msg := make([]byte, getRandMessageSize())
	crutils.Randomize(msg)
	err := sendMessage(msg, t)
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
		processIncomingEphemeralPub(raw)
		sess.state |= InviteReceived
	}

	if (t & ACK) != 0 {
		// todo: check if it was encrypted with my eph key
		sess.state |= AckReceived
	}

	if (t & Quit) != 0 {
		sess.state |= QuitReceived
		err := sendRandomMessage(Quit | QuitAck)
		if err != nil {
			fmt.Printf("Failed to send QuitAck: %s \n", err.Error())
			sess.state = UnexpectedClosed
		} else {
			sess.state |= QuitSent
			sess.state |= QuitAckSent
		}
	}

	if (t & QuitAck) != 0 {
		if (sess.state & QuitSent) != 0 {
			sess.state |= GracefullyClosed
		} else {
			sess.state = UnexpectedClosed
			fmt.Println("Warning: session interrupted")
		}
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
