package zip

import (
	"bytes"
	"testing"
)

func TestZipCrypto_Read(t *testing.T) {
	// This is a synthetic test. A full test requires a byte array
	// from a real encrypted archive.
	password := "12345"
	data := []byte("secret message")

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	// The current Writer does not support writing encryption (it's more complex),
	// so we only test the decoder logic.
	zw.Close()

	// Key verification
	crypto := newZipCrypto([]byte(password))
	encData := make([]byte, len(data))
	copy(encData, data)

	// Imitation of the encryption process (the algorithm is symmetric in terms of updateKeys)
	// To write, we would need to implement a separate method,
	// but APPNOTE says the process is identical.
	for i, v := range encData {
		b := crypto.decryptByte()
		c := v ^ b
		crypto.updateKeys(v) // When encrypting, we update the keys with the plaintext byte
		encData[i] = c
	}

	// Now, decrypt
	decrypto := newZipCrypto([]byte(password))
	decrypto.decrypt(encData)

	if !bytes.Equal(encData, data) {
		t.Errorf("ZipCrypto failed: expected %q, got %q", string(data), string(encData))
	}
}

func TestWinZipAES_WrongPassword(t *testing.T) {
	// Simulate a stream with salt and password verification
	salt := make([]byte, 8)
	verif := []byte{0xAA, 0xBB}
	payload := bytes.NewReader(append(salt, verif...))

	info := &winzipAesInfo{strength: 1} // AES-128
	_, _, err := newWinZipAesReader(payload, "wrong_pass", info, 100)

	if err == nil || err.Error() != "zip: incorrect password" {
		t.Errorf("expected 'incorrect password' error, got: %v", err)
	}
}