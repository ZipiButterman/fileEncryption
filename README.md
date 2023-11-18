# fileEncryption - explenation
A system to encrypt files in client and send them to server
A client regist to the system and then create per of keys (private and public) the public he send to the server
the server create AES key and encrypt it with the public key. Then the client get the encrypted key and decrypt it with the private key
after it, the client encrypt the file with the key and send it to the server. 
The server decrypt it with the key and keep create a new file with the decryption file.
(The verification is done by CRC) 
