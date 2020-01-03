package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/terminal"
)

var connexxions []net.Conn
var mx sync.Mutex

func init() {
	connexxions = make([]net.Conn, 0, 32000)
}

func printServerInfo() {
	var n int
	mx.Lock()
	n = len(connexxions)
	mx.Unlock()
	fmt.Printf("%d peers connected\n", n)
}

func verifyServerHandshake(msg []byte) bool {
	_, err := asym.Decrypt(serverKey, msg)
	if err != nil {
		fmt.Printf("verification failed: %s \n", err)
		return false
	}
	return true
}

func addServerConnexxion(c net.Conn) {
	mx.Lock()
	defer mx.Unlock()
	connexxions = append(connexxions, c)
}

func removeServerConnexxion(target net.Conn) {
	mx.Lock()
	defer mx.Unlock()

	for i, c := range connexxions {
		if c == target {
			last := len(connexxions) - 1
			connexxions[i] = connexxions[last]
			connexxions = connexxions[:last]
		}
	}
}

func shutdownServer(ln net.Listener) {
	err := ln.Close()
	if err != nil {
		fmt.Printf("Failed to close listener: %s \n", err.Error())
	}

	var sz int
	mx.Lock()
	sz = len(connexxions)
	for _, c := range connexxions {
		go c.Close()
	}
	mx.Unlock()

	for i := 0; i < 200 && sz > 0; i++ {
		time.Sleep(50 * time.Millisecond)
		mx.Lock()
		sz = len(connexxions)
		mx.Unlock()
	}

	if sz > 0 {
		fmt.Printf("Incorrect shutdown: failed to close %d connexxions\n", sz)
	}
}

func runServerConnexxionsLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}

		msg, err := receivePacket(conn)
		if err != nil {
			fmt.Printf("Connexxion error: %s \n", err.Error())
			conn.Close()
			continue
		}

		if !verifyServerHandshake(msg) {
			fmt.Println("Connexxion verification failed")
			conn.Close()
			continue
		}

		addServerConnexxion(conn)
		go runServerMessageLoop(conn)
	}
}

func runServerMessageLoop(conn net.Conn) {
	for {
		msg, err := receivePacket(conn)
		if err != nil {
			break
		}
		forwardPacketToClients(conn, msg)
	}

	removeServerConnexxion(conn)
}

func forwardPacketToClients(src net.Conn, msg []byte) {
	mx.Lock()
	defer mx.Unlock()

	for _, c := range connexxions {
		if c != src {
			go sendPacket(c, msg)
		}
	}
}

func runServer() {
	ln, err := net.Listen("tcp", getDefaultIP())
	if err != nil {
		fmt.Printf("Server error: %s \n", err.Error())
		return
	}

	fmt.Println("xserver v.1 started")
	common.PrintPublicKey(&serverKey.PublicKey)
	go runServerConnexxionsLoop(ln)

	for {
		cmd := terminal.PlainTextInput()
		if strings.Contains(string(cmd), "q") {
			break
		} else if strings.Contains(string(cmd), "i") {
			printServerInfo()
		}
	}

	shutdownServer(ln)
}