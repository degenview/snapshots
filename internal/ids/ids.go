// Package ids generates the random identifiers and secrets the service hands
// out. Everything comes from crypto/rand and is sampled without modulo bias.
package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

const (
	// ImageIDLen is the length of a public image id: 62^10 ≈ 2^59.5.
	ImageIDLen = 10
	// DeleteSecretLen is the length of a delete secret: 62^24 ≈ 2^143.
	DeleteSecretLen = 24
	// TokenLen is the random part of an upload token (≈ 2^190).
	TokenLen = 32
	// TokenPrefix marks upload tokens so secret scanners can find them.
	TokenPrefix = "dvs_"
)

// Random returns n characters drawn uniformly from [0-9A-Za-z].
func Random(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	// 248 = 62*4: bytes at or above it are rejected so every symbol is equally likely.
	const limit = 248
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("ids: reading randomness: %w", err)
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, alphabet[int(b)%len(alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// ImageID returns a new public image id.
func ImageID() (string, error) { return Random(ImageIDLen) }

// DeleteSecret returns a new delete secret.
func DeleteSecret() (string, error) { return Random(DeleteSecretLen) }

// Token returns a new upload token including its prefix.
func Token() (string, error) {
	r, err := Random(TokenLen)
	if err != nil {
		return "", err
	}
	return TokenPrefix + r, nil
}

// ValidImageID reports whether s has exactly the shape of an image id. Every
// storage and database lookup by id goes through this first.
func ValidImageID(s string) bool {
	return validRandom(s, ImageIDLen)
}

// ValidDeleteSecret reports whether s has the shape of a delete secret.
func ValidDeleteSecret(s string) bool {
	return validRandom(s, DeleteSecretLen)
}

// ValidRandom reports whether s is exactly n characters of the random alphabet.
func ValidRandom(s string, n int) bool { return validRandom(s, n) }

func validRandom(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		default:
			return false
		}
	}
	return true
}

// Hash returns the hex SHA-256 of a high-entropy secret. These secrets are
// random, so a fast unsalted hash is sufficient; it only has to make a leaked
// database useless for authenticating.
func Hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
