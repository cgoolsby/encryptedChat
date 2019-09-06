package main

import (
  "os"
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
  "flag"
  )

type KeyEx struct {
  X  *big.Int
  Y  *big.Int
}

func main() {
  var rOrD = flag.Bool("t", true, "Stipulate t=false for one end of chat")
  var otherIP = flag.String("ip", "127.0.0.1", "Stipulate the IP of the partner")
  var port = flag.String("port", ":8889", "Stipulate the Port to communicate on")  //":####"
  flag.Parse()

  key, connection := keyExchange(*otherIP, *port, *rOrD)
//  startChat(*otherIP, *port, *rOrD, key)
  startChat(*otherIP, *port, *rOrD, key, connection)
}
func keyExchange(otherIP, port string, rOrD bool) ([]byte, net.Conn) {
  if rOrD {
    return ke_Receive(port)
  } else {
    return ke_Dial(otherIP, port)
  }
}

func ke_Receive(port string) ([]byte, net.Conn) {
  fmt.Println("launching server..")
  listener, _ := net.Listen("tcp", port)
  connection, _ := listener.Accept()
  key := keyExchangeDetails(connection)
  return key, connection
}

func ke_Dial(otherIP, port string) ([]byte, net.Conn) {
  address := fmt.Sprintf("%s%s", otherIP, port)
  fmt.Printf("Establishing TCP connection with %s\n", address)
  connection, _ := net.Dial("tcp", address)
  key := keyExchangeDetails(connection)
  return key, connection
}

func keyExchangeDetails(connection net.Conn) []byte {
  privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  var pubKey KeyEx
  pubKey.X = privKey.PublicKey.X
  pubKey.Y = privKey.PublicKey.Y

  enc := gob.NewEncoder(connection)
  dec := gob.NewDecoder(connection)
  enc.Encode(pubKey)
  err := dec.Decode(&pubKey)
  if err != nil {
    fmt.Println(err)
  }

  shared, _ := privKey.PublicKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
  if err != nil {
    fmt.Println(err)
  }

  ke := sha256.Sum256(shared.Bytes())
  fmt.Println("Key Exchange Completed - the 'secret' is : ")
  fmt.Println(ke)
  return ke[:]
}

func startChat(otherIP, port string, rOrD bool, key []byte, connection net.Conn) {
  if rOrD {
    startListen(port, key, connection)
  } else {
    startSend(otherIP, port, key, connection)
  }
}
func startListen(port string, key []byte, connection net.Conn) error {
  defer connection.Close()
  for {
//I think there is a possible race condition here    
    message, _ := bufio.NewReader(connection).ReadString('\n')
    fmt.Print("Message Received:", string(message))
    response := encode(key, string(message))
    fmt.Printf("Sending Encoding: %x\n", response)
    connection.Write(append(response,'\n'))

    readerStdIn := bufio.NewReader(os.Stdin)
    fmt.Print("Text to send: ")
    text, _ := readerStdIn.ReadString('\n')
    fmt.Fprintf(connection, text + "\n")
    fmt.Println("Sent: %s", text)
    ciphertext, _ := bufio.NewReader(connection).ReadBytes('\n')
    fmt.Printf("Recieved Back : %x\n", ciphertext)
    fmt.Println("Decoded to: %s", decode(ciphertext[:len(ciphertext)-1], key))
  }
  return nil
}

func startSend(otherIP, port string, key []byte, connection net.Conn) error {
  for {
    readerStdIn := bufio.NewReader(os.Stdin)
    fmt.Print("Text to send: ")
    text, _ := readerStdIn.ReadString('\n')
    fmt.Fprintf(connection, text + "\n")
    fmt.Println("Sent: %s", text)
    ciphertext, _ := bufio.NewReader(connection).ReadBytes('\n')
    fmt.Printf("Recieved Back : %x\n", ciphertext)
    fmt.Println("Decoded to: %s", decode(ciphertext[:len(ciphertext)-1], key))
//I think there is a possible race condition here    
    message, _ := bufio.NewReader(connection).ReadString('\n')
    fmt.Print("Message Received:", string(message))
    response := encode(key, string(message))
    fmt.Printf("Sending Encoding: %x\n", response)

    connection.Write(append(response,'\n'))
  }
  return nil
}

func encode(key []byte, message string) []byte {
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")//using single nonce in v1 to avoid race condition
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

