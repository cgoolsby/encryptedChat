# encryptedChat
encryptedChat


Hey! I thought I'd do this in git so you could see how I went about developing this.  Feel free to ask me any questions!


Step One:
 2 EC2s in AWS to act as infrastructure to complete public key exchange and open a chat client between the two.

Step Two:
  Write a short golang to ensure that I can indeed do a private/pub exchange that results in a shared secret
  I will use ECDH for this exchange

Step Three:
  Write some golang to setup listeners on each client to perform the exchange

Step Four:
  Implement sending packets with encrypted chat and decrypting them for reading.
