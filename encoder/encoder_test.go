package encoder

import "testing"

func TestRSAEncoder_EncodeAndDecode_DataSouldEqual(t *testing.T) {
    rsa, err := NewRSAEncoder(3000)
    if err != nil {
        t.Fatalf("an error occured: %v", err)
    }

    str := []string{"hello", " world"}
    data := make([]byte, 0)

    for i := 0; i < 256; {
        if i % 2 == 0 {
            data = append(data, []byte(str[0])...)
            i += len(str[0])
        } else {
            data = append(data, []byte(str[1])...)
            i += len(str[1]) - 1
        }
    }    
    encoded, err := rsa.Encode([]byte(data))
    if err != nil {
        t.Fatalf("an error occured: %v", err)
    }
    decoded, err := rsa.Decode(encoded)
    if err != nil {
        t.Fatalf("an error occured: %v", err)
    }

    decodedStr := string(decoded)
    if string(data) != decodedStr {
        t.Fatalf("strings are not equal. want %s got %s", string(data), decodedStr)
    }
}
