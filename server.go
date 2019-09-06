package main

import (
  "encoding/gob"
  "net"
  "fmt"
  "bufio"
  "crypto/rand"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/sha256"
  "crypto/aes"
  "crypto/cipher"
  "encoding/hex"
  "math/big"
  )

type KeyEx struct {
  X  *big.Int
  Y  *big.Int
}

func main() {
  fmt.Println("launching server..")

  listener, _ := net.Listen("tcp", ":8088")

  connection, _ := listener.Accept()

  privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  var pubKey KeyEx
  pubKey.X = privKey.PublicKey.X
  pubKey.Y = privKey.PublicKey.Y
  enc := gob.NewEncoder(connection)
  dec := gob.NewDecoder(connection)
  var fromClient  KeyEx
  err := dec.Decode(&fromClient)
  if err != nil {
    fmt.Println(err)
  }
  enc.Encode(pubKey)

  connection.Close()

  shared, _ := privKey.PublicKey.Curve.ScalarMult(fromClient.X, fromClient.Y, privKey.D.Bytes())

  ke := sha256.Sum256(shared.Bytes())
  key := ke[:]


  connection, _ = listener.Accept()


  for {
    message, _ := bufio.NewReader(connection).ReadString('\n')
    fmt.Print("Message Received:", string(message))
    newmessage := encode(key, string(message))
    fmt.Printf("Sending Encoding: %x\n", newmessage)

    connection.Write(append(newmessage,'\n'))
  }
}
func encode(key []byte, message string) []byte {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
//	key, _ = hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")
	plaintext := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext
}

func decode(ciphertext, key []byte) string {
        // Load your secret key from a safe place and reuse it across multiple
        // Seal/Open calls. (Obviously don't use this example key for anything
        // real.) If you want to convert a passphrase to a key, use a suitable
        // package like bcrypt or scrypt.
        // When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
  //      key, _ = hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
        nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")

        block, err := aes.NewCipher(key)
        if err != nil {
                panic(err.Error())
        }

        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
                panic(err.Error())
        }

        plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
        if err != nil {
                panic(err.Error())
        }

        return string(plaintext)
}

