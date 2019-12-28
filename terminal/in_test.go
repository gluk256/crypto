package terminal

import (
	"math/rand"
	"testing"
	"time"

	"github.com/gluk256/crypto/algo/primitives"
)

func TestShuffle(t *testing.T) {
	singleShuffleTest(t, true)
	singleShuffleTest(t, false)
}

func singleShuffleTest(t *testing.T, ext bool) {
	seed := time.Now().Unix()
	rand.Seed(seed)

	initParams(ext)
	copy(scrambledAlphabet, alphabet)
	shuffleAlphabet()
	ok := primitives.IsDeepNotEqual(alphabet, scrambledAlphabet, len(alphabet))
	if !ok {
		t.Fatalf("shuffle test failed with seed %d", seed)
	}
}
