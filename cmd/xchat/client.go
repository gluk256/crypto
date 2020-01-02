package main

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/crypto/terminal"
)

const (
	MessageType = 5

	Handshake    = byte(0)
	EphemeralPub = byte(1)
	EphemeralSym = byte(2)
	TextType     = byte(64)
	FileType     = byte(65)
)

var (
	incomingMsgCnt uint32
	outgoingMsgCnt uint32
)

func runHandshakeWithServer(conn net.Conn, local bool) error {
	var pub *ecdsa.PublicKey
	if local {
		pub = &serverKey.PublicKey
	} else {
		// todo: parse params
	}

	b := make([]byte, 256)
	crutils.Randomize(b)
	encrypted, err := asym.Encrypt(pub, b) // todo: get the key from params (unless server is on localhost)
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
		go processPacketC(p)
	}
	c.Close()
}

func runClient(flags string) {
	local := strings.Contains(flags, "l")
	if local {
		err := loadKeys()
		if err != nil {
			fmt.Printf("Failed to load private key: %s \n", err.Error())
			return
		}
	}

	fmt.Println("xchat v.1 started")
	conn, err := net.Dial("tcp", string("127.0.0.1:")+getPort())
	if err != nil {
		fmt.Printf("Client error: %s \n", err.Error())
		return
	}

	fmt.Println("connected to server")
	err = runHandshakeWithServer(conn, local)
	if err != nil {
		fmt.Printf("Handshake failed: %s \n", err.Error())
	}

	go runClientMessageLoop(conn)

	for {
		s := terminal.PlainTextInput()
		data := s
		t := TextType

		if len(s) == 0 {
			continue
		} else if isExitCmd(s) {
			break
		} else if isSendFileCmd(s) {
			t = FileType
			data, err = loadFile()
			if err != nil {
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
	suffix[MessageType] = msgType
	p = append(p, suffix...)
	// todo: encryption here
	return p, nil
}

func processPacketC(p []byte) error {
	// todo: decrypt, extract header, and decide what to do accordingly
	sz := len(p)
	if sz < SuffixSize {
		return errors.New("message is too small")
	}
	suffix := p[sz-SuffixSize:]
	p = p[:sz-SuffixSize]
	t := suffix[MessageType]
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
