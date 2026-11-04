package ids

import (
	"strings"
	"testing"
)

func TestRandomLengthAndAlphabet(t *testing.T) {
	for _, n := range []int{1, 10, 24, 32, 257} {
		s, err := Random(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != n {
			t.Fatalf("len %d != %d", len(s), n)
		}
		for _, c := range s {
			if !strings.ContainsRune(alphabet, c) {
				t.Fatalf("unexpected char %q", c)
			}
		}
	}
}

func TestRandomUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20000; i++ {
		s, _ := ImageID()
		if seen[s] {
			t.Fatalf("collision after %d ids", i)
		}
		seen[s] = true
	}
}

func TestRandomIsRoughlyUniform(t *testing.T) {
	counts := map[rune]int{}
	const n = 62 * 2000
	s, _ := Random(n)
	for _, c := range s {
		counts[c]++
	}
	if len(counts) != 62 {
		t.Fatalf("saw %d symbols, want 62", len(counts))
	}
	for c, k := range counts {
		// expected 2000, σ≈44; ±400 is >9σ.
		if k < 1600 || k > 2400 {
			t.Fatalf("symbol %q appeared %d times", c, k)
		}
	}
}

func TestTokenShape(t *testing.T) {
	tok, err := Token()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, TokenPrefix) || len(tok) != len(TokenPrefix)+TokenLen {
		t.Fatalf("bad token %q", tok)
	}
}

func TestValidators(t *testing.T) {
	id, _ := ImageID()
	if !ValidImageID(id) {
		t.Fatal("generated id invalid")
	}
	sec, _ := DeleteSecret()
	if !ValidDeleteSecret(sec) || ValidImageID(sec) {
		t.Fatal("secret validation wrong")
	}
	for _, bad := range []string{"", "short", id + "x", "../../etc/", "abc/def123", "abc.def123", "abcdef123\x00", "abcdef 123", "ééééé", strings.Repeat("a", 11)} {
		if ValidImageID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHash(t *testing.T) {
	a1, a2 := Hash("a"), Hash("a")
	if a1 == Hash("b") || len(a1) != 64 || a1 != a2 {
		t.Fatal("hash misbehaves")
	}
}
