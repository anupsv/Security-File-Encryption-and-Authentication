# Security-File-Encryption-and-Authentication

### This is a Python application that can be used to encrypt and sign a file to be used for any purpose. 
- The sender knows the public key of the destination, and has a private key to sign the file. 
- The application can also be used by the receiver to decrypt the file using their private key and to verify the signature using the public key of the sender. 
- The application is extremely efficient by using a combination of public key crypto system and symmteric key crypto system.

## Usage

### Encryption
python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file

### Decryption
python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file


# To be done

- End to End Encryption System.
