package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/example/seavault-fast/internal/xcrypto/argon2"
)

const (
	DefaultKDFIterations = 600000
	DefaultScryptN       = 32768
	DefaultScryptR       = 8
	DefaultScryptP       = 1
	DefaultArgon2Time    = 1
	DefaultArgon2Memory  = 64 * 1024
	DefaultArgon2Threads = 4
	keySize              = 32
	wrapAAD              = "seavault-wrap-v1"
	indexAAD             = "seavault-index-v1"
	manifestAADPrefix    = "seavault-manifest-v2:"
	chunkAADPrefix       = "seavault-chunk-v1:"
)

var (
	indexMagic    = []byte("SVIDX1\n")
	manifestMagic = []byte("SVMAN2\n")
	chunkMagic    = []byte("SVCHNK1\n")
)

type Keys struct {
	MasterKey []byte
	IndexKey  []byte
}

func DefaultKDFConfig() KDFConfig {
	return KDFConfig{Algorithm: "ARGON2ID", Time: DefaultArgon2Time, MemoryKiB: DefaultArgon2Memory, Parallelism: DefaultArgon2Threads}
}

func FastKDFConfigForTests() KDFConfig {
	return KDFConfig{Algorithm: "SCRYPT", ScryptN: 16, ScryptR: 1, ScryptP: 1}
}

func NormalizeKDFConfig(cfg KDFConfig, creating bool) (KDFConfig, error) {
	alg := normalizeKDF(cfg.Algorithm)
	if alg == "" {
		cfg = DefaultKDFConfig()
		alg = normalizeKDF(cfg.Algorithm)
	}
	salt := cfg.Salt
	switch alg {
	case "argon2id", "argon2-id":
		if cfg.Time <= 0 {
			cfg.Time = DefaultArgon2Time
		}
		if cfg.MemoryKiB <= 0 {
			cfg.MemoryKiB = DefaultArgon2Memory
		}
		if cfg.Parallelism <= 0 {
			cfg.Parallelism = DefaultArgon2Threads
		}
		if cfg.Parallelism > 255 {
			return KDFConfig{}, errors.New("argon2id parallelism must be <= 255")
		}
		if cfg.MemoryKiB < 8*cfg.Parallelism {
			cfg.MemoryKiB = 8 * cfg.Parallelism
		}
		cfg.Algorithm = "ARGON2ID"
		cfg.Iterations, cfg.ScryptN, cfg.ScryptR, cfg.ScryptP = 0, 0, 0, 0
	case "scrypt":
		if cfg.ScryptN == 0 {
			cfg.ScryptN = DefaultScryptN
		}
		if cfg.ScryptR == 0 {
			cfg.ScryptR = DefaultScryptR
		}
		if cfg.ScryptP == 0 {
			cfg.ScryptP = DefaultScryptP
		}
		if _, err := scryptKey([]byte("probe"), []byte("salt"), cfg.ScryptN, cfg.ScryptR, cfg.ScryptP, 1); err != nil {
			return KDFConfig{}, err
		}
		cfg.Algorithm = "SCRYPT"
		cfg.Iterations, cfg.MemoryKiB, cfg.Time, cfg.Parallelism = 0, 0, 0, 0
	case "pbkdf2", "pbkdf2-hmac-sha256":
		if cfg.Iterations <= 0 {
			cfg.Iterations = DefaultKDFIterations
		}
		cfg.Algorithm = "PBKDF2-HMAC-SHA256"
		cfg.ScryptN, cfg.ScryptR, cfg.ScryptP, cfg.MemoryKiB, cfg.Time, cfg.Parallelism = 0, 0, 0, 0, 0, 0
	default:
		return KDFConfig{}, fmt.Errorf("unsupported KDF algorithm %q", cfg.Algorithm)
	}
	cfg.Salt = salt
	if !creating && cfg.Salt == "" {
		return KDFConfig{}, errors.New("vault KDF salt is missing")
	}
	return cfg, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

func randomHex(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid AES key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deriveWrapKey(password string, cfg KDFConfig) ([]byte, error) {
	cfg, err := NormalizeKDFConfig(cfg, false)
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(cfg.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode KDF salt: %w", err)
	}
	switch normalizeKDF(cfg.Algorithm) {
	case "pbkdf2-hmac-sha256":
		return pbkdf2Key([]byte(password), salt, cfg.Iterations, keySize, sha256.New), nil
	case "scrypt":
		return scryptKey([]byte(password), salt, cfg.ScryptN, cfg.ScryptR, cfg.ScryptP, keySize)
	case "argon2id", "argon2-id":
		return argon2.IDKey([]byte(password), salt, uint32(cfg.Time), uint32(cfg.MemoryKiB), uint8(cfg.Parallelism), keySize), nil
	default:
		return nil, fmt.Errorf("unsupported KDF algorithm %q", cfg.Algorithm)
	}
}

func normalizeKDF(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	return strings.ReplaceAll(s, "_", "-")
}

func deriveSubkey(master []byte, info string) []byte {
	return hkdfSHA256(master, nil, []byte(info), keySize)
}

func wrapKeys(password string, cfg KDFConfig, keys Keys) (string, string, error) {
	if len(keys.MasterKey) != keySize || len(keys.IndexKey) != keySize {
		return "", "", errors.New("invalid key bundle")
	}
	wrapKey, err := deriveWrapKey(password, cfg)
	if err != nil {
		return "", "", err
	}
	aead, err := newAESGCM(wrapKey)
	if err != nil {
		return "", "", err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return "", "", err
	}
	bundle := append(append([]byte{}, keys.MasterKey...), keys.IndexKey...)
	ct := aead.Seal(nil, nonce, bundle, []byte(wrapAAD))
	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ct), nil
}

func unwrapKeys(password string, cfg KDFConfig, nonceB64, ctB64 string) (Keys, error) {
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return Keys{}, fmt.Errorf("decode wrapped-key nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return Keys{}, fmt.Errorf("decode wrapped keys: %w", err)
	}
	wrapKey, err := deriveWrapKey(password, cfg)
	if err != nil {
		return Keys{}, err
	}
	aead, err := newAESGCM(wrapKey)
	if err != nil {
		return Keys{}, err
	}
	bundle, err := aead.Open(nil, nonce, ct, []byte(wrapAAD))
	if err != nil {
		return Keys{}, errors.New("unlock failed: wrong password or damaged vault configuration")
	}
	if len(bundle) != 2*keySize {
		return Keys{}, fmt.Errorf("unexpected key bundle length %d", len(bundle))
	}
	return Keys{MasterKey: append([]byte(nil), bundle[:keySize]...), IndexKey: append([]byte(nil), bundle[keySize:]...)}, nil
}

func hmacHex(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func constantTimeStringEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

func encodeEncrypted(magic, nonce, ct []byte) []byte {
	out := make([]byte, 0, len(magic)+len(nonce)+len(ct))
	out = append(out, magic...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

func decodeEncrypted(magic []byte, nonceSize int, data []byte) ([]byte, []byte, error) {
	if !bytes.HasPrefix(data, magic) {
		return nil, nil, errors.New("bad encrypted object magic")
	}
	rest := data[len(magic):]
	if len(rest) < nonceSize {
		return nil, nil, errors.New("encrypted object too short")
	}
	return rest[:nonceSize], rest[nonceSize:], nil
}

func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	if iter <= 0 {
		panic("PBKDF2 iteration count must be positive")
	}
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for x := range t {
				t[x] ^= u[x]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	var okm []byte
	var previous []byte
	counter := byte(1)
	for len(okm) < length {
		expand := hmac.New(sha256.New, prk)
		expand.Write(previous)
		expand.Write(info)
		expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		okm = append(okm, previous...)
		counter++
	}
	return okm[:length]
}
