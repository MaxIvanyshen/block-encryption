package encoder

import "testing"

func TestRSAEncoder_EncodeAndDecode_DataSouldEqual(t *testing.T) {
    rsa, err := NewRSAEncoder(1024)
    if err != nil {
        t.Fatalf("an error occured: %v", err)
    }

    msg := "hello world"
    encoded, err := rsa.Encode([]byte(msg))
    if err != nil {
        t.Fatalf("an error occured: %v", err)
    }
    decoded, err := rsa.Decode(encoded)
    if err != nil {
        t.Fatalf("an error occured: %v", err)
    }

    decodedStr := string(decoded)
    if msg != decodedStr {
        t.Fatalf("strings are not equal. want %s got %s", msg, decodedStr)
    }
}
