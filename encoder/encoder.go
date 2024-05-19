package encoder

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto"
	"errors"
	"fmt"
)

type Encoder interface {
    Encode(data []byte) []byte
    Decode(data []byte) []byte
}

type RSAEncoder struct {
    key *rsa.PrivateKey
}

var RSAEncoderCreationError = errors.New("Error while creating RSA encoder")
var RSAEncodingError = errors.New("Error while encoding with RSA")
var RSADecodingError = errors.New("Error while decoding with RSA")

func NewRSAEncoder(bits int) (*RSAEncoder, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
        return &RSAEncoder{}, fmt.Errorf(
            "%v: couldn't generate keys: %v", RSAEncoderCreationError, err,
        )
	}

    return &RSAEncoder{key: key}, nil
}

func (encoder *RSAEncoder) Encode(data []byte) ([]byte, error) {
    encryptedBytes, err := rsa.EncryptOAEP(
        sha256.New(),
        rand.Reader,
        &encoder.key.PublicKey,
        data,
        nil,
    )
    if err != nil {
        return make([]byte, 0), fmt.Errorf(
            "%v: couldn't encrypt your data: %v", RSAEncodingError, err,
        )
    }   

    return encryptedBytes, nil
}

func(decoder *RSAEncoder) Decode(data []byte) ([]byte, error) {
    decryptedBytes, err := decoder.key.Decrypt(nil, data, &rsa.OAEPOptions{Hash: crypto.SHA256})
    if err != nil {
        return make([]byte, 0), fmt.Errorf("%v: couldn't decrypt the message: %v", RSADecodingError, err)
    }

    return decryptedBytes, nil
}

