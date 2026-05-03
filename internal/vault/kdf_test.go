package vault

import (
	"encoding/hex"
	"testing"
)

func TestScryptRFC7914Vector(t *testing.T) {
	got, err := scryptKey([]byte(""), []byte(""), 16, 1, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("scrypt vector mismatch\n got %x\nwant %x", got, want)
	}
}
