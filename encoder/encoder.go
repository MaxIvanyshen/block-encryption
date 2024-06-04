package encoder

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto"
	"errors"
	"math"
	"fmt"
)

type Encoder interface {
    Encode(data []byte) ([]byte, error)
    Decode(data []byte) ([]byte, error)
}

type RSAEncoder struct {
    key *rsa.PrivateKey
    bits int
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

    return &RSAEncoder{key: key, bits: bits}, nil
}

func (encoder *RSAEncoder) Encode(data []byte) ([]byte, error) {
    sha := sha256.New()
    randReader := rand.Reader
    done := make(chan interface{})

    defer close(done)

    chunkStream := chunkGenerator(done, data, encoder.bits)
    out := make([]byte, 0)

    for chunk := range chunkStream {

        encryptedBytes, err := rsa.EncryptOAEP(
            sha,
            randReader,
            &encoder.key.PublicKey,
            chunk,
            nil,
        )

        if err != nil {
            return make([]byte, 0), fmt.Errorf(
                "%v: couldn't encrypt your data: %v", RSAEncodingError, err,
            )
        }   

        out = append(out, encryptedBytes...)
    }


    return out, nil
}

func(decoder *RSAEncoder) Decode(data []byte) ([]byte, error) {
    done := make(chan interface{})
    defer close(done)
    chunkStream := chunkGenerator(done, data, decoder.bits)

    out := make([]byte, 0)

    for chunk := range chunkStream {
        decryptedBytes, err := decoder.key.Decrypt(nil, chunk, &rsa.OAEPOptions{Hash: crypto.SHA256})
        if err != nil {
            return make([]byte, 0), fmt.Errorf("%v: couldn't decrypt the message: %v", RSADecodingError, err)
        }

        out = append(out, decryptedBytes...)
    }


    return out, nil
}

func chunkGenerator(done chan interface{}, bytes []byte, bits int) <-chan []byte {
    stream := make(chan []byte)

    chunkSize := int(math.Floor(float64(bits / 8)))
    if chunkSize == 0 {
        chunkSize = 1
    }

    go func() {
        defer close(stream)
        
        for i := 0; i < len(bytes); i += chunkSize {

            if i + chunkSize >= len(bytes) {
                chunkSize = len(bytes) - i
            }

            chunk := bytes[i:i+chunkSize]
            
            select {
            case <-done:
                return
            case stream<-chunk:
            }
        }
    }()

    return stream    
}

