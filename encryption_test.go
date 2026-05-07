package zip

import (
	"bytes"
	"testing"
)

func TestZipCrypto_Read(t *testing.T) {
	// Это синтетический тест. Для полноценного теста нужен байтовый массив
	// реального зашифрованного архива.
	password := "12345"
	data := []byte("secret message")

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	// В текущем Writer нет поддержки записи шифрования (она сложнее),
	// поэтому мы проверяем только логику дешифратора.
	zw.Close()

	// Проверка ключей
	crypto := newZipCrypto([]byte(password))
	encData := make([]byte, len(data))
	copy(encData, data)

	// Имитация процесса шифрования (алгоритм симметричен в плане updateKeys)
	// Для записи нам нужно было бы реализовать отдельный метод,
	// но APPNOTE говорит, что процесс идентичен.
	for i, v := range encData {
		b := crypto.decryptByte()
		c := v ^ b
		crypto.updateKeys(v) // При шифровании обновляем ключи открытым байтом
		encData[i] = c
	}

	// Теперь дешифруем
	decrypto := newZipCrypto([]byte(password))
	decrypto.decrypt(encData)

	if !bytes.Equal(encData, data) {
		t.Errorf("ZipCrypto failed: expected %q, got %q", string(data), string(encData))
	}
}

func TestWinZipAES_WrongPassword(t *testing.T) {
	// Имитируем поток с солью и проверкой пароля
	salt := make([]byte, 8)
	verif := []byte{0xAA, 0xBB}
	payload := bytes.NewReader(append(salt, verif...))

	info := &winzipAesInfo{strength: 1} // AES-128
	_, _, err := newWinZipAesReader(payload, "wrong_pass", info, 100)

	if err == nil || err.Error() != "zip: incorrect password" {
		t.Errorf("expected 'incorrect password' error, got: %v", err)
	}
}