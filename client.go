package main

import (
  "fmt"
  "bufio"
  "net"
  "os"
  "encoding/gob"
  "crypto/rand"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/sha256"
  "crypto/aes"
  "crypto/cipher"
  "math/big"
"encoding/hex"
)

type KeyEx struct {
  X  *big.Int
  Y  *big.Int
}

func main() {

  connection, _ := net.Dial("tcp", "54.212.101.137:8088")
  enc := gob.NewEncoder(connection)
  dec := gob.NewDecoder(connection)

  var fromServer KeyEx
  privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  var pubKey KeyEx
  pubKey.X = privKey.PublicKey.X
  pubKey.Y = privKey.PublicKey.Y
  enc.Encode(pubKey)
  err := dec.Decode(&fromServer)
  if err != nil {
    fmt.Println(err)
}

  fmt.Println(fromServer)

  shared, _ := privKey.PublicKey.Curve.ScalarMult(fromServer.X, fromServer.Y, privKey.D.Bytes())

  ke :=sha256.Sum256(shared.Bytes())
  key := ke[:]

  connection.Close()
  connection, _ = net.Dial("tcp", "54.212.101.137:8088")

  for {

    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Text to send: ")
    text, _ := reader.ReadString('\n')
    fmt.Fprintf(connection, text + "\n")
    fmt.Println("Sent: %s", text)
    ciphertext, _ := bufio.NewReader(connection).ReadBytes('\n')
    fmt.Printf("Recieved Back : %x\n", ciphertext)
    fmt.Println("Decoded to: %s", decode(ciphertext[:len(ciphertext)-1], key))
  }
}

func decode(ciphertext, key []byte) string {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
//	key, _ = hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
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
