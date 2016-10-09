#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json, base64
import ntpath
import os, sys, os.path
from optparse import OptionParser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class pycrypt:

    # initializes the various environments needed for encryption and decryption
    # does checks on file etc.
    def __init__(self, pub_key_path, priv_key_path, plain_or_crypt_data_path, output_file, email_attachment,
                 type_of_operation):

        self.pub_key_path = pub_key_path
        self.type_of_operation = type_of_operation
        self.priv_key_path = priv_key_path
        self.plain_or_crypt_data_path = plain_or_crypt_data_path
        self.output_file = output_file
        self.verify_file_exists()
        self.load_keys()
        self.get_key_length()
        self.read_input_file()
        # len of gcm iv which is going to be used to generate the random iv.
        self.gcm_iv = 16
        self.file_attachment_path = email_attachment
        self.fileInfo = {}
        # an unique identifier of the receiver.
        self.receiver_name = "receiver@something.com"

    # this function reads the input file contents which needs to be encrypted.
    def read_input_file(self):
        self.msg_data = open(self.plain_or_crypt_data_path, "r").read()
        self.msg_data = bytes(bytearray(self.msg_data))

    # this function computes hash of a given data using SHA512 hashing algorithm and returns the output.
    def hash_data(self, data):
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(data)
        msg_digest = digest.finalize()
        return msg_digest

    # this function encrypts the data, sets up ENV's and returns the blob with needs to be transmitted.
    def encrypt_data(self):
        self.setup_encrypter_env()

        encryptor = self.encrypter_cipher.encryptor()
        self.prepare_msg_data_with_attachment()
        hash_of_msg = self.hash_data(self.msg_data)

        # In Sign & Encrypt, enclosing recipients name, because this will link the outer layer's key to the inner layer
        # By signing recipients name into message, sender explicitly identifies receiver as intended recipient
        # A ---> B: {{Receiver, msg}a}B

        sig = self.generate_signature(self.receiver_name + hash_of_msg)
        encrypted_data = encryptor.update(sig + self.msg_data) + encryptor.finalize()
        tag = encryptor.tag

        rsaenc = self.rsa_encrypt(self.aes_key)
        # IV + Tag + rsa encrypted data + Encrypted Data
        return self.iv + tag + rsaenc + encrypted_data

        # self.decrypt_data(ct)

    def decrypt_data(self, alldata):

        iv = alldata[:self.gcm_iv]
        tag = alldata[self.gcm_iv: self.gcm_iv + 16]

        rsaenc = alldata[self.gcm_iv + 16:self.gcm_iv + 16 + self.rsaenc_length]
        encrypted_data = alldata[self.gcm_iv + 16 + self.rsaenc_length:]

        self.aes_key = self.rsa_decrypt(rsaenc)

        try:
            self.setup_decrypter_env(tag, iv)
        except:
            print "Failed to setup decrypt ENV."
            sys.exit()

        try:
            decryptor = self.decrypter_cipher.decryptor()
            sig_msg = decryptor.update(encrypted_data) + decryptor.finalize()
        except:
            print "Failed to decrypt data"
            sys.exit()

        sig = sig_msg[:self.signature_length]
        msg = sig_msg[self.signature_length:]

        print "-" * 50
        try:
            self.verify_signature(sig, self.receiver_name + self.hash_data(msg))
            print "Signature verified."
        except:
            print "Signature verification failed."
            sys.exit()

        print "-" * 50
        split_msg = msg.split("\r\n\r\n\r\n\r\n")

        if len(split_msg[1]) > 2:
            print "Attachment Detected."
            filename = split_msg[1].split("\r\r\n")[0]
            filedata = split_msg[1].split("\r\r\n")[1]

            with open("attachment-{}".format(filename), "w+") as f:
                f.writelines(filedata)
        else:
            print "No attachment detected."
        return split_msg[0]

    # this function sets up the encryption env by initializing the Cipher.
    def setup_encrypter_env(self):
        self.iv = os.urandom(self.gcm_iv)
        self.encrypter_cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(self.iv), backend=default_backend())
        print "-" * 50
        print "Encryption ENV has been setup."

    # this function sets up the decryption env by using the iv, tag retrieved from the message.
    def setup_decrypter_env(self, tag, iv):
        self.decrypter_cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv, tag), backend=default_backend())
        print "-" * 50
        print "Decryption ENV has been setup."

    # this function loads a given private key and returns the object.
    # the file must be in PEM format.
    def load_private_key(self):
        with open(self.priv_key_path, "rb") as key_file:
            try:
                return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
            except:
                print "-" * 50
                print "Could not load the pem private key file. Please Check."
                sys.exit()

    # this function loads the public key. Opens the file and uses cryptography's serialization method to load the
    # PEM verison of the public key.
    def load_public_key(self):
        with open(self.pub_key_path, "rb") as key_file:
            try:
                return serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            except:
                print "-" * 50
                print "Could not load the pem public key file. Please Check."
                sys.exit()

    # this function performs the RSA encryption given the data (usually the symmetric key) to be encrypted.
    def rsa_encrypt(self, msg):
        try:
            ciphertext = self.public_key.encrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                                   algorithm=hashes.SHA512(), label=None))
        except:
            print "Could not encrypt the data."
            sys.exit()

        return ciphertext

    # this function does rsa decryption given the cipher text.
    def rsa_decrypt(self, ciphertext):
        try:
            plaintext = self.private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                                          algorithm=hashes.SHA512(), label=None))
        except:
            print "-" * 50
            print "Could not decrypt the data."
            sys.exit()

        return plaintext

    # this function loads the public and private keys.
    def load_keys(self):
        self.public_key = self.load_public_key()
        self.private_key = self.load_private_key()

    # this function generates the signature on the given data using the private key.
    def generate_signature(self, msg):
        try:
            signer = self.private_key.signer(
                padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA512())
        except:
            print "Could not create signature for given data."
            sys.exit()

        signer.update(msg)
        sig = signer.finalize()
        return sig

    # once a public key is loaded, this function is used to verify the signature on the data it was signed.
    def verify_signature(self, sig, msg):
        verifier = self.public_key.verifier(sig, padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                                             salt_length=padding.PSS.MAX_LENGTH), hashes.SHA512())
        verifier.update(msg)
        verifier.verify()

    # this function performs the different tasks before encryption and writes the final encrypted output to the
    # specified file
    def encrypt_and_write(self):

        if self.file_attachment_path:

            print "---" * 50
            print "Attachment Detected"
            print "Doing checks on file : ", self.file_attachment_path
            self.do_file_checks()

        print "-" * 50
        print "Initiating Encryption...."
        data = self.encrypt_data()
        print "-" * 50
        print "Encryption done successfully."
        print "-" * 50
        print "Trying to write to file : ", self.output_file

        try:
            with open(self.output_file, "w+") as f:
                f.write(base64.encodestring(data))
        except:
            print "Could not write encrypted data to file. Sorry :("
            sys.exit()

        print "-" * 50
        print "Data has been written to file : {}".format(self.output_file)
        print "*" * 50

    # this function splits the data into respective blocks and decrypts and also verifies signature.
    def decrypt_and_write(self):
        print "-" * 50
        print "Trying to Read file {}....".format(self.plain_or_crypt_data_path)

        # reading encrypted output from file.
        try:
            filedata = open(self.plain_or_crypt_data_path, "r").read()
        except:
            print "Could not read the file : {}. Sorry :(".format(self.plain_or_crypt_data_path)
            sys.exit()

        # base 64 decoding the string
        print "-" * 50
        print "File data read successfully."
        base64decoded = base64.decodestring(filedata)

        # decrypting the data
        print "-" * 50
        print "Trying to decrypt data....."
        data = self.decrypt_data(base64decoded)
        print "-" * 50
        print "Decryption done..."

        # writing decrypted data to file
        print "-" * 50
        print "Trying to write to file...."
        try:
            with open(self.output_file, "w+") as f:
                f.write(data)
        except:
            print "Sorry, could not write to file : {}".format(self.output_file)
            sys.exit()
        print "-" * 50
        print "Data has been written to file : {}".format(self.output_file)

    def do_file_checks(self):

        if not self.file_attachment_path:
            return

        if not os.path.exists(self.file_attachment_path):
            print "File specified was not found : {}".format(self.file_attachment_path)
            d = raw_input("Would you like to re-enter the correct file path ? ")

            if d == "n":
                d = raw_input("Do you wish to continue without attaching the file (y/n) ? ")
                if d == "n":
                    sys.exit()
            elif d == "y":
                self.file_attachment_path = raw_input("Please enter the full path of the attachment :  ")
                self.do_file_checks()
        else:
            self.get_file_info()

    def get_file_info(self):
        self.fileInfo["filename"] = ntpath.basename(self.file_attachment_path)
        with open(self.file_attachment_path, 'r') as myfile:
            self.fileInfo["filedata"] = myfile.read()

    def prepare_msg_data_with_attachment(self):
        dictstring = ""
        dictstring += self.fileInfo["filename"] + "\r\r\n"
        dictstring += self.fileInfo["filedata"]
        self.msg_data = self.msg_data + "\r\n\r\n\r\n\r\n" + dictstring

    # This function verifies if the given key files exist or not. Throws error and exists gracefully if not found.
    def verify_file_exists(self):

        if not os.path.exists(self.pub_key_path):
            print "Public Key file not found : {}".format(self.pub_key_path)
            sys.exit()
        elif not os.path.exists(self.priv_key_path):
            print "Private Key file not found : {}".format(self.priv_key_path)
            sys.exit()
        elif not os.path.exists(self.plain_or_crypt_data_path):
            print "File to be encrypted not found : {}".format(self.plain_or_crypt_data_path)
            sys.exit()

    # identifies the key length and calculates the respective expected signature lengths
    # also has option of changing the AES key length. Currently at max with 32 * 8 = 256 bit key length.
    def get_key_length(self):

        if self.type_of_operation is "encrypt":
            self.key_size = self.private_key.key_size
            # the signature is generated by the private key of sender
            self.signature_length = self.private_key.key_size / 8
            self.rsaenc_length = self.public_key.key_size / 8

            if self.signature_length % 2 != 0 and self.signature_length > 0:
                print "Looks like there's something wrong with the private key. The length of the key found is : {}".\
                    format(self.signature_length * 8)
                sys.exit()

            if self.rsaenc_length % 2 != 0 and self.rsaenc_length > 0:
                print "Looks like there's something wrong with the public key. The length of the key found is : {}".\
                    format(self.signature_length * 8)
                sys.exit()


        elif self.type_of_operation is "decrypt":
            self.key_size = self.public_key.key_size
            # the signature length corresponds to the length of the public key
            self.signature_length = self.public_key.key_size / 8
            self.rsaenc_length = self.private_key.key_size / 8

            if self.signature_length % 2 != 0 and self.signature_length > 0:
                print "Looks like there's something wrong with the public key. The length of the key found is : {}".\
                    format(self.signature_length * 8)
                sys.exit()

            if self.rsaenc_length % 2 != 0 and self.rsaenc_length > 0:
                print "Looks like there's something wrong with the private key. The length of the key found is : {}".\
                    format(self.signature_length * 8)
                sys.exit()

        else:
            print "The file {} is not supported. Either you are using a weak key or something so strong that we don't "\
                    "really have a need for that or some other file instead of a key.".format(self.key_size)

            sys.exit()


        self.aes_key = os.urandom(32)
        # print self.signature_length

if __name__ == "__main__":

    bashOptParser = OptionParser()
    bashOptParser.add_option("-d", dest="decrypt", help="Please enter file path to private key", default=False)
    bashOptParser.add_option("-e", dest='encrypt', help="Please enter file path to public key", default=False)
    bashOptParser.add_option("-f", dest='filepath', help="Please enter full file path to attach file", default=False)
    (options, args) = bashOptParser.parse_args()

    if len(args) != 3 or (not options.decrypt and not options.encrypt):
        print "Please provide the correct number of arguments."
        sys.exit()

    if options.encrypt:
        pycrypter = pycrypt(options.encrypt, args[0], args[1], args[2], options.filepath, "encrypt")
        pycrypter.encrypt_and_write()
    elif options.decrypt:
        pycrypter = pycrypt(args[0], options.decrypt, args[1], args[2], options.filepath, "decrypt")
        pycrypter.decrypt_and_write()

