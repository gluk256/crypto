package main

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

type Session struct {
	permPeerKey    *ecdsa.PublicKey
	ephPeerKey     *ecdsa.PublicKey
	incomingMsgCnt uint32
	outgoingMsgCnt uint32
	ack            bool
}

const (
	MessageTypeIndex = 5

	Ack          = byte(8)
	EphemeralPub = byte(9)
	TextType     = byte(64)
	FileType     = byte(65)
)

var (
	serverIP string
	sess     Session

	whiteList [][]byte
	blackList [][]byte
)

func resetSession() {
	sess.permPeerKey = nil
	sess.ephPeerKey = nil
	sess.incomingMsgCnt = 0
	sess.outgoingMsgCnt = 0
	sess.ack = false
}

func startSession(conn net.Conn, override bool) bool {
	if sess.permPeerKey == nil || override {
		key, err := common.ImportPubKey()
		if err != nil {
			return false
		} else {
			sess.permPeerKey = key
			sess.ack = false
		}
	}

	myEphemeral, err := asym.ExportPubKey(&ephemeralKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to export pub key: %s \n", err.Error())
		return false
	}

	sig, err := asym.Sign(serverKey, myEphemeral)
	if err != nil {
		fmt.Printf("Failed to sign pub key: %s \n", err.Error())
		return false
	}

	msg := append(myEphemeral, sig...)
	err = sendMessage(conn, msg, EphemeralPub)
	if err != nil {
		return false
	}

	// todo: wait for the completion
	// todo: sometimes send new msgs
	return true
}

func sendHandshakeToServer(conn net.Conn) error {
	b := make([]byte, 256)
	crutils.Randomize(b)
	encrypted, err := asym.Encrypt(remoteServerPubKey, b)
	if err == nil {
		err = sendPacket(conn, encrypted)
	}
	return err
}

func runClientMessageLoop(c net.Conn) {
	for {
		p, err := receivePacket(c)
		if err != nil {
			break
		}
		go processPacket(p)
	}
	c.Close()
}

func isCmd(b []byte) bool {
	s := string(b)
	return s[0] == '\\' || s[0] == '/'
}

func runClientCmdLoop(conn net.Conn) {
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
				startSession(conn, true)
				continue
			} else {
				continue
			}
		}

		err = sendMessage(conn, data, t)
		if err != nil {
			break
		}
	}
}

func sendMessage(conn net.Conn, data []byte, t byte) error {
	p, err := packMessage(data, t)
	if err == nil {
		err = sendPacket(conn, p)
	}
	if err != nil {
		fmt.Printf("Failed to send message: %s \n", err.Error())
	}
	return err
}

func packMessage(p []byte, msgType byte) ([]byte, error) {
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
	common.PrintPublicKey(&clientKey.PublicKey)

	err = sendHandshakeToServer(conn)
	if err != nil {
		fmt.Printf("Handshake failed: %s \n", err.Error())
	}

	go runClientMessageLoop(conn)

	if sess.permPeerKey != nil || strings.Contains(flags, "a") {
		if !startSession(conn, false) {
			return
		}
	}

	runClientCmdLoop(conn)
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
		} else {
			sess.incomingMsgCnt = nonce
		}
	} else {
		sess.incomingMsgCnt++
	}
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

func processMessage(raw []byte, t byte, nonce uint32) {
	// todo: process other types
	if t == TextType {
		fmt.Printf("[%03d][%s] \n", nonce, string(raw))
	} else if t == FileType {
		h := crutils.Sha2(raw)
		name := fmt.Sprintf("%x", h)
		common.SaveData(name, raw)
		fmt.Printf("[%03d]: saved msg as file %s \n", nonce, name)
	} else {
		fmt.Println("unknown message type")
	}
}

func processPacket(p []byte) {

	// todo: decrypt, extract header, and decide what to do accordingly

	raw, t, nonce := parsePacket(p)
	if raw != nil {
		checkNonce(nonce)
		processMessage(raw, t, nonce)
	}
}
