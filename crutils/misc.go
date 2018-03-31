package crutils

import (
	"fmt"
)

func Reverse(a []int) {
	i := 0
	j := len(a) - 1
	for i < j {
		a[i], a[j] = a[j], a[i]
	}
}

func Misctest() {
	fmt.Printf("success \n")
}
