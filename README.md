## Crypt12 Decryptor
Tool for decrypting WhatsApp Crypt12 databases

## Java

### Usage

`java -classpath "lib/bc.jar:." Decrypt msgstore.db.crypt12 key`

### Compile

`javac -classpath "lib/bc.jar:." Decrypt.java`

![img](/assets/terminal.jpg)


## AES GCM

#### Inputs and Outputs to GCM

GCM has two operations, authenticated encryption and authenticated decryption. The authenticated encryption operation has four inputs, each of which is a bit string:

- A secret key K, whose length is appropriate for the underlying block cipher.
- An initialization vector IV, that can have any number of bits between 1 and 2^64. For a fixed value of key, each IV value must be distinct, but need not have equal lengths. 96-bit IV values can be processed more efficiently, so that length is recommended for situations in which efficiency is critical.
- A plaintext P, which can have any number of bits between 0 and 2^39 - 256.
- Additional authenticated data (AAD), which is denoted as A. This data is authenticated, but not encrypted, and can have any number of bits between 0 and 2^64.

The There two Outputs

- A ciphertext C whose length is exactly that of the plaintext P.
- An authentication tag T, whose length can be any value between 0 and 128. The length of the tag is denoted as t.

The authenticated decryption operation has five inputs: K, IV, C, A and T. It has only a single output, either the plaintext value P or a special symbol 'FAIL' that indicates that the inputs are not authentic. A ciphertext C, initialization vector IV, additional authenticated data A and tag T are authentic for key K when they are generated with the encrypt operation with inputs K, IV, A and P, for some plaintext P. The authenticated decrypt operation will, with high probability, return 'FAIL' when its inputs were not created by the encrypt operation with the identical key.
The additional authenticated data A is used to protect information that needs to be authenticated, but which must be left unencrypted. When using GCM to secure network protocol, this input could include addresses, ports, sequence numbers, protocol version numbers, and other fields that indicate how the plaintext should be handled, forwarded, or processed. In many situations, its desirable to authenticate these fields, though they must be left in the clear for the network to function properly. when this data is included in the AAD, authentication is provided without copying the data into the ciphertext.
The primary purpose of the IV is to be a nonce, that is, to be distinct for each invocation of the encryption operation for a fixed key. It is acceptable for the IV to be generated randomly, as long as the distinctness of the IV is highly likely. The IV is authenticated, and it is not necessary to include it in in the AAD field.

#### Decryption:
The authenticated decryption operation is similar to the encrypt operation, but with the order of the hash step and encrypt step reversed. The equations are as follows:

<img src="https://raw.githubusercontent.com/mgp25/Crypt12-Decryptor/master/assets/dec2.jpeg" width="400" height="200"/>

The authenticated decryption operation

<img src="https://raw.githubusercontent.com/mgp25/Crypt12-Decryptor/master/assets/auth.jpeg" width="400" height="400"/>

Using GCM to decrypt and verify the authenticity of a packet

<img src="https://raw.githubusercontent.com/mgp25/Crypt12-Decryptor/master/assets/dec.jpeg" width="400" height="200"/>


__

Reference: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
