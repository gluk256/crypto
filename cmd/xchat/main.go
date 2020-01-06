package main

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/asym"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
)

const (
	PrefixSize = 4
	SuffixSize = 6
)

var (
	masterKey          []byte
	serverKey          *ecdsa.PrivateKey
	clientKey          *ecdsa.PrivateKey
	ephemeralKey       *ecdsa.PrivateKey
	remoteServerPubKey *ecdsa.PublicKey
)

func cleanup() {
	crutils.AnnihilateData(masterKey)
	asym.AnnihilatePrivateKey(serverKey)
	asym.AnnihilatePrivateKey(clientKey)
	asym.AnnihilatePrivateKey(ephemeralKey)
}

func getFileEncryptionKey() []byte {
	return keccak.Digest(masterKey, 256)
}

func loadKeys(flags string) error {
	fmt.Println("loading cert") // todo: delete
	cert, err := common.LoadCertificate()
	masterKey = cert
	if err != nil {
		return err
	}

	fmt.Println("importing server key") // todo: delete
	sk := keccak.Digest(cert, 32)
	defer crutils.AnnihilateData(sk)
	serverKey, err = asym.ImportPrivateKey(sk)
	if err != nil {
		return err
	}

	if isServer(flags) {
		return nil
	}

	fmt.Println("generating eph") // todo: delete
	ephemeralKey, err = asym.GenerateKey()
	if err != nil {
		return err
	}

	fmt.Println("loading master pass") // todo: delete
	if strings.Contains(flags, "i") {
		fmt.Println("======================> WARNING: insecure version without password, only use for test purposes!")
		masterKey[0]++
	} else {
		pass := common.GetPassword(flags)
		masterKey = primitives.XorInplace(masterKey, pass, 256)
		crutils.AnnihilateData(pass)
	}

	fmt.Println("loading client key") // todo: delete
	ck := keccak.Digest(masterKey, 288)
	ck = ck[256:]
	fmt.Printf("%x\n", ck) // todo: delete
	defer crutils.AnnihilateData(ck)
	clientKey, err = asym.ImportPrivateKey(ck)
	if err != nil {
		return err
	}

	fmt.Println("done") // todo: delete
	return err
}

func isServer(flags string) bool {
	return len(flags) == 0
}

func getDefaultIP() string {
	return string("127.0.0.1:") + getDefaultPort()
}

func getDefaultPort() string {
	return "26594"
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
	fmt.Println("USAGE: xchat flags [ip_address[:port]] [server_pub_key] [client_pub_key]")
	fmt.Println("\t -z chat client")
	fmt.Println("\t -l client running on the same machine as server (server-related params are not required)")
	fmt.Println("\t -s secure password")
	fmt.Println("\t -i insecure (without password)")
	fmt.Println("\t -c initiate new chat session")
	fmt.Println("\t -y restart previous session")
	fmt.Println("\t -h help")
}

func helpInternal() {
	fmt.Println("COMMANDS")
	fmt.Println("\\f: send file")
	fmt.Println("\\w: whitelist another peer")
	fmt.Println("\\c: initiate new chat session with current peer")
	fmt.Println("\\y: restart session")
	fmt.Println("\\n: initiate new chat session with new peer")
	fmt.Println("\\d: delete another peer form whitelist")
	fmt.Println("\\D: delete current peer form whitelist")
	fmt.Println("\\p: add session password for additional symmetric encryption")
	fmt.Println("\\P: add session password (secure mode)")
	fmt.Println("\\b: output debug info")
	fmt.Println("\\h: help")
	fmt.Println("\\e: exit current session")
	fmt.Println("\\q: quit")
}

func main() {
	var flags string
	if len(os.Args) > 1 {
		flags = os.Args[1]
	}

	if strings.Contains(flags, "h") {
		help()
		return
	}

	defer cleanup()
	err := loadKeys(flags)
	if err != nil {
		fmt.Printf("Failed to load private key: %s \n", err.Error())
		return
	}

	if isServer(flags) {
		runServer()
	} else {
		runClient(flags)
	}
}
