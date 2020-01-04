package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
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
	permPubHex     []byte
	permPeerKey    *ecdsa.PublicKey
	ephPeerKey     *ecdsa.PublicKey
	incomingMsgCnt uint32
	outgoingMsgCnt uint32
	ack            bool
}

const (
	debugMode = true

	MinMessageSize   = 256 // todo: use it for padding the thex
	MessageTypeIndex = 5

	Invite       = byte(1)
	ACK          = byte(2)
	CloseSession = byte(4)
	CloseAck     = byte(8)
	TextType     = byte(64)
	FileType     = byte(128)

	ProtoThreshold = CloseAck
	UserThreshold  = TextType
)

var (
	socket    net.Conn
	serverIP  string
	sess      Session
	whiteList [][]byte
)

func resetSession() {
	sess.permPubHex = nil
	sess.permPeerKey = nil
	sess.ephPeerKey = nil
	sess.incomingMsgCnt = 0
	sess.outgoingMsgCnt = 0
	sess.ack = false
}

func isListed(arr [][]byte, pub []byte) bool {
	for _, b := range arr {
		if bytes.Equal(b, pub) {
			return true
		}
	}
	return false
}

func invitePeerToChatSession(override bool) bool {
	if sess.permPeerKey == nil || override {
		key, err := common.ImportPubKey()
		if err != nil {
			return false
		} else {
			sess.permPeerKey = key
			sess.ack = false
		}
	}

	pub, err := asym.ExportPubKey(sess.permPeerKey)
	if err != nil {
		whiteList = append(whiteList, pub)
	}

	err = sendMyEphemeralKey(false)
	if err != nil {
		fmt.Printf("Failed to send ephemeral pub key: %s \n", err.Error())
		return false
	}

	fmt.Println("New session successfully initiated")
	return waitForAck()
}

func sendMyEphemeralKey(ack bool) error {
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
	if ack {
		t |= ACK
	}

	return sendMessage(msg, t)
}

func waitForAck() bool {
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if sess.ack && sess.ephPeerKey != nil {
			fmt.Println("New session successfully established")
			return true
		}
	}

	fmt.Println("New session failed: ack was not received")
	return false
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
	for {
		s := terminal.PlainTextInput()
		if len(s) == 0 {
			continue
		}
		data := s
		t := TextType

		if isCmd(s) {
			if strings.Contains(string(s), "h") {
				helpInternal()
				continue
			} else if strings.Contains(string(s), "q") {
				break
			} else if strings.Contains(string(s), "f") {
				t = FileType
				data, err = loadFile()
				if err != nil {
					continue
				}
			} else if strings.Contains(string(s), "a") {
				resetSession()
				invitePeerToChatSession(true)
				continue
			} else if strings.Contains(string(s), "i") {
				printDiagnosticInfo()
			} else {
				continue
			}
		}

		err = sendMessage(data, t)
		if err != nil {
			break
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

func loadConnexxionParams(flags string) bool {
	if strings.Contains(flags, "l") {
		serverIP = getDefaultIP()
		remoteServerPubKey = &serverKey.PublicKey
	} else if len(os.Args) < 4 {
		fmt.Println("Can not connect to the server: not enough parameters")
		return false
	} else {
		serverIP = os.Args[2]
		if !strings.Contains(serverIP, ":") {
			serverIP += getDefaultPort()
		}

		k, err := asym.ImportPubKey([]byte(os.Args[3]))
		if err != nil {
			fmt.Println("Failed to import remote server's pub key")
			return false
		}
		remoteServerPubKey = k

		if len(os.Args) > 4 {
			k, err = asym.ImportPubKey([]byte(os.Args[4]))
			if err != nil {
				fmt.Println("Failed to import the peer's pub key")
				return false
			}
			sess.permPeerKey = k
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

	if sess.permPeerKey != nil || strings.Contains(flags, "a") {
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

	// if sess.ephPeerKey != nil {
	// 	return
	// }

	if !isListed(whiteList, pub) {
		fmt.Printf("\nSession invite received from: %x\n", pub)
		fmt.Println("If you trust this key, you should add it explicitly [use '\\a' command]")
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
	sess.permPeerKey = perm
	sess.ephPeerKey = eph

	err = sendMyEphemeralKey(true)
	if err != nil {
		fmt.Printf("Error sending EPH msg: %s \n", err.Error())
		return
	}

	fmt.Println("New session initiated by remote peer")
	waitForAck()
}

func getRandMessageSize() (r int) {
	r = MinMessageSize
	r += int(crutils.PseudorandomUint64()) % MinMessageSize
	return r
}

func sendRandomMessage(t byte) error {
	msg := make([]byte, getRandMessageSize())
	crutils.Randomize(msg)
	return sendMessage(msg, t)
}

func processUserMessage(raw []byte, t byte, nonce uint32) {
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
		fmt.Printf("[%03d]{msg received: type = %d, size = %d} \n", nonce, int(t), len(raw))
	}

	if t > ProtoThreshold {
		fmt.Printf("unknown protocol message type: %d \n", int(t))
	}

	if (t & Invite) != 0 {
		processIncomingEphemeralPub(raw)
	}

	if (t & ACK) != 0 {
		sess.ack = true // todo: check if sess.ephKey == sig
	}

	if (t & CloseSession) != 0 {
		// todo: implement
	}

	if (t & CloseAck) != 0 {
		// todo: implement?
	}
}

// todo: add param sig after decryption is implemented
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
	fmt.Printf("eph: %s, perm: %s, in = %d, out = %d, ack = %v \n", eph, perm, sess.incomingMsgCnt, sess.outgoingMsgCnt, sess.ack)
}
