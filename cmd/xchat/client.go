package main

import (
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

const (
	MessageTypeIndex = 5

	Handshake    = byte(0)
	EphemeralPub = byte(1)
	EphemeralSym = byte(2)
	TextType     = byte(64)
	FileType     = byte(65)
)

var (
	serverIP       string
	incomingMsgCnt uint32
	outgoingMsgCnt uint32
)

func invitePeerToChatSession() {
	// todo: implement
}

func runHandshakeWithServer(conn net.Conn) error {
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
		go processPacketClient(p)
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
			} else if strings.Contains(string(s), "p") {
				invitePeerToChatSession()
				continue
			} else {
				continue
			}
		}

		msg, err := prepareMessage(data, t)
		if err == nil {
			err = sendPacket(conn, msg)
		}
		if err != nil {
			fmt.Printf("Failed to send message: %s \n", err.Error())
			break
		}
	}
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
			fmt.Println("Can not connect to the server: not enough parameters")
			return false
		}
		remoteServerPubKey = k
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
	err = runHandshakeWithServer(conn)
	if err != nil {
		fmt.Printf("Handshake failed: %s \n", err.Error())
	}

	go runClientMessageLoop(conn)
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

func prepareMessage(p []byte, msgType byte) ([]byte, error) {
	suffix := make([]byte, SuffixSize)
	outgoingMsgCnt++
	binary.LittleEndian.PutUint32(suffix, outgoingMsgCnt)
	suffix[MessageTypeIndex] = msgType
	p = append(p, suffix...)
	// todo: encryption here
	return p, nil
}

func processPacketClient(p []byte) error {
	// todo: decrypt, extract header, and decide what to do accordingly
	sz := len(p)
	if sz < SuffixSize {
		return errors.New("message is too small")
	}
	suffix := p[sz-SuffixSize:]
	p = p[:sz-SuffixSize]
	t := suffix[MessageTypeIndex]
	num := binary.LittleEndian.Uint32(suffix)

	if (t & 64) == 0 {
		info := string("wrong message type")
		fmt.Println(info)
		return errors.New(info)
	}

	incomingMsgCnt++
	if num != incomingMsgCnt {
		fmt.Printf("unexpected msg number: [%d vs. %d] \n", num, incomingMsgCnt)
	}

	if t == TextType {
		fmt.Printf("[%03d][%s] \n", num, string(p))
	} else if t == FileType {
		h := crutils.Sha2(p)
		name := fmt.Sprintf("%x", h)
		common.SaveData(name, p)
		fmt.Printf("[%03d]: saved msg as file %s \n", num, name)
	} else {
		info := string("unknown message type")
		fmt.Println(info)
		return errors.New(info)
	}

	return nil
}
