package main

import "fmt"

func help() {
	fmt.Println("xfile encrypts/decrypts a file with a password")
	fmt.Println("USAGE: xfile flags srcFile [dstFile]")
	fmt.Println("\t r random password")
	fmt.Println("\t s secure password input")
	fmt.Println("\t x extra secure password input")
	fmt.Println("\t p simplest encryption (no salt, dst_size = src_size)")
	fmt.Println("\t h help")
}

func main() {

}
