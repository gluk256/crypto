package main

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
)

const (
	PrefixSize = 4
	SuffixSize = 6
)

var (
	serverKey *ecdsa.PrivateKey
	clientKey *ecdsa.PrivateKey
)

func cleanup() {
	asym.AnnihilatePrivateKey(serverKey)
	asym.AnnihilatePrivateKey(clientKey)
}

func loadKeys() error {
	h, err := common.LoadCertificate()
	if err == nil {
		serverKey, err = asym.ImportPrivateKey(h[len(h)-32:])
		if err == nil {
			clientKey, err = asym.ImportPrivateKey(h[:32])
		}
	}
	return err
}

func main() {
	if len(os.Args) < 2 || strings.Contains(os.Args[1], "h") {
		help()
		return
	}

	defer cleanup()
	loadKeys()

	flags := os.Args[1]
	if strings.Contains(flags, "s") {
		runServer()
	} else {
		runClient(flags)
	}
}

func getPort() string {
	return "26594"
}

func isExitCmd(s []byte) bool {
	cmd := string(s)
	return cmd == "q" || cmd == "\\q" || cmd == "/q"
}

func isSendFileCmd(s []byte) bool {
	cmd := string(s)
	return cmd == "\\f" || cmd == "/f"
}

func sendPacket(conn net.Conn, msg []byte) error {
	prefix := make([]byte, PrefixSize)
	binary.LittleEndian.PutUint32(prefix, uint32(len(msg)))
	n, err := conn.Write(prefix)
	if err != nil {
		return err
	}
	if n != PrefixSize {
		return errors.New("prefix not sent")
	}

	n, err = conn.Write(msg)
	if n != len(msg) {
		err = errors.New("message not sent")
	}

	return err
}

func readNBytes(c net.Conn, sz uint32) ([]byte, error) {
	msg := make([]byte, sz)
	n, err := c.Read(msg)
	if err != nil {
		return nil, err
	}
	if uint32(n) != sz {
		return nil, errors.New("wrong message size")
	}
	return msg, nil
}

func receivePacket(c net.Conn) (msg []byte, err error) {
	const limit = 20 * 1024 * 1024
	prefix, err := readNBytes(c, PrefixSize)
	if err == nil {
		sz := binary.LittleEndian.Uint32(prefix)
		if sz > limit {
			return nil, errors.New("huge message")
		}
		msg, err = readNBytes(c, sz)
	}
	return msg, err
}

func help() {
	fmt.Printf("xchat v.0.%d \n", crutils.CipherVersion)
	fmt.Println("encrypted chat between remote peers, with ephemeral keys and forward secrecy")
	fmt.Println("USAGE: xchat flags [ip_address:port] [server_pub_key] [peer_pub_key]")
	fmt.Println("\t -s server")
	fmt.Println("\t -c client")
	fmt.Println("\t -l client running on the same machine as server")
	fmt.Println("\t -s secure password")
	fmt.Println("\t -i insecure - without password")
	fmt.Println("\t -h help")
}
