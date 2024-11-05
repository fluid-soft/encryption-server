package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/dh/x448"
)

type KeyPair struct {
	PrivateKey x448.Key
	PublicKey  x448.Key
	ExpiresAt  time.Time
}

func GenerateNewKeyPair() (*KeyPair, error) {
	var privateKey, publicKey x448.Key
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	x448.KeyGen(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ExpiresAt:  time.Now().UTC().Add(24 * time.Hour).Truncate(24 * time.Hour),
	}, nil
}

func GetEncodedPublicKey(publicKey x448.Key) string {
	return base64.StdEncoding.EncodeToString(publicKey[:])
}

func DeriveSharedSecret(privateKey x448.Key, publicKey x448.Key) ([]byte, error) {
	var sharedSecret x448.Key
	ok := x448.Shared(&sharedSecret, &privateKey, &publicKey)
	if !ok {
		return nil, errors.New("failed to derive shared secret: invalid public key")
	}

	// use SHA-256 to derive a 32-byte key from the shared secret
	hash := sha256.Sum256(sharedSecret[:])
	return hash[:], nil
}

func EncryptAES(data, key []byte) ([]byte, error) {
	// enforce 32 bytes key for increased security
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key size: %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func DecryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

func CompressAndEncryptAES(data, key []byte) ([]byte, error) {
	// compress the data
	var compressedBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuffer)
	_, err := gzipWriter.Write(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %v", err)
	}
	err = gzipWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("closing gzip writer failed: %v", err)
	}

	// encrypt the compressed data
	return EncryptAES(compressedBuffer.Bytes(), key)
}

func DecryptAndDecompressAES(data, key []byte) ([]byte, error) {
	// decrypt the data
	decrypted, err := DecryptAES(data, key)
	if err != nil {
		return nil, err
	}

	// decompress the decrypted data
	gzipReader, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader failed: %v", err)
	}
	defer gzipReader.Close()

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %v", err)
	}

	return decompressed, nil
}
