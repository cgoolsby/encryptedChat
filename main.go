package main
import (
  "fmt"
  "crypto/elliptic"
  "crypto/ecdsa"
  "crypto/rand"
  "crypto/sha256"
  )



func main() {
  fmt.Println("Begin Public Exchange Test:")
  privKeyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    panic(err)
  }
  privKeyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    panic(err)
  }
  
  fmt.Printf("Private Key A : %x\n", privKeyA.D)
  fmt.Printf("Private Key B : %x\n\n", privKeyB.D)

  pubKeyA := privKeyA.PublicKey
  pubKeyB := privKeyB.PublicKey

  fmt.Printf("Public Key A : %x, %x\n", pubKeyA.X, pubKeyA.Y)
  fmt.Printf("Public Key B : %x, %x\n\n", pubKeyB.X, pubKeyB.Y)

  toA, _ := pubKeyA.Curve.ScalarMult(pubKeyA.X, pubKeyA.Y, privKeyB.D.Bytes())
  toB, _ := pubKeyB.Curve.ScalarMult(pubKeyB.X, pubKeyB.Y, privKeyA.D.Bytes())

  sharedA := sha256.Sum256(toB.Bytes())
  sharedB := sha256.Sum256(toA.Bytes())

  fmt.Printf("SharedA: %x\n", sharedA)
  fmt.Printf("SharedB: %x\n\n", sharedB)




}

