# Secure-Communication-System
 In this project, I had to design and (partially) implement a secure communication system between two parties.
The criteria I included is listed below:

1.) The two parties have each other’s RSA public key. Each of them holds his/her own RSA
private key.

2.) Each party’s message (from a .txt file) is encrypted using AES before sending it to
another party.

3.) The AES key used in 2) is encrypted using the receiver’s RSA public key. The encrypted
AES key is sent together with the encrypted message obtained from 2). 

4.) Message authentication code should be appended to data transmitted. You are free to
choose the specific protocol of MAC.

5.) The receiver should be able to successfully authenticate, decrypt the message, and read
the original message. 

I had to use local files as the channel to
simulate the communication in the network.

