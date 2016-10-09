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
    def __init__(self, pub_key_path, priv_key_path, plain_or_crypt_data_path, output_file, email_attachment):

        self.pub_key_path = pub_key_path
        self.priv_key_path = priv_key_path
        self.plain_or_crypt_data_path = plain_or_crypt_data_path
        self.output_file = output_file
        self.verify_file_exists()
        self.load_keys()
        self.get_key_length()
        self.read_input_file()
        self.gcm_iv = 16
        self.file_attachment_path = email_attachment
        self.fileInfo = {}
        self.receiver_name = "receiver@something.com"

    def read_input_file(self):

        self.msg_data = open(self.plain_or_crypt_data_path, "r").read()
        self.msg_data = bytes(bytearray(self.msg_data))

    def hash_data(self, data):

        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(data)
        msg_digest = digest.finalize()
        return msg_digest

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

        print "-" * 50
        print "Encrypted Tag (GCM Auth) len: ", len(tag)
        print "-" * 50

        print "-" * 50
        print "Length of Encrypted Msg Data : ", len(encrypted_data)
        print "-" * 50

        rsaenc = self.rsa_encrypt(self.aes_key)

        print "-" * 50
        print "Signature len : ", len(sig)
        print "Signature : ", base64.encodestring(sig)
        print "IV len : ", len(self.iv)
        print "IV : ", base64.encodestring(self.iv)
        print "Tag len : ", len(tag)
        print "RSA Enc Length : ", len(rsaenc)
        print "AES Key : ", base64.encodestring(self.aes_key)
        print "AES Key Len : ", len(self.aes_key)
        print "-" * 50

        # IV + Tag + rsa encrypted data + Encrypted Data
        return self.iv + tag + rsaenc + encrypted_data

        # self.decrypt_data(ct)


    def decrypt_data(self, alldata):

        iv = alldata[:self.gcm_iv]
        tag = alldata[self.gcm_iv: self.gcm_iv + 16]

        rsaenc = alldata[self.gcm_iv + 16:self.gcm_iv + 16 + self.signature_length]
        encrypted_data = alldata[self.gcm_iv + 16 + self.signature_length:]

        print base64.encodestring(iv)
        print 50 * "-"
        print base64.encodestring(tag)

        self.aes_key = self.rsa_decrypt(rsaenc)
        # print base64.encodestring(aes_key)

        self.setup_decrypter_env(tag, iv)

        decryptor = self.decrypter_cipher.decryptor()
        sig_msg = decryptor.update(encrypted_data) + decryptor.finalize()

        sig = sig_msg[:self.signature_length]
        msg = sig_msg[self.signature_length:]

        try:
            self.verify_signature(sig, self.receiver_name + self.hash_data(msg))
            print "Signature verified."
        except:
            print "Signature verification failed."
            sys.exit()
        print "-" * 50

        split_msg = msg.split("\r\n\r\n")

        if len(split_msg[1]) > 2:
            print "Attachment Detected."
            json_loaded_attachment = json.loads(split_msg[1])
            print json_loaded_attachment
            with open("attachment-{}".format(json_loaded_attachment["filename"]), "w+") as f:
                f.writelines(json_loaded_attachment["filedata"])
        else:
            print "No attachment detected."
        return split_msg[0]

    # this function sets up the encryption env by initializing the Cipher.
    def setup_encrypter_env(self):
        self.iv = os.urandom(self.gcm_iv)
        self.encrypter_cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(self.iv), backend=default_backend())

    # this function sets up the decryption env by using the iv, tag retrieved from the message.
    def setup_decrypter_env(self, tag, iv):
        self.decrypter_cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv, tag), backend=default_backend())

    def load_private_key(self):
        with open(self.priv_key_path, "rb") as key_file:
            try:
                return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
            except:
                print "Could not load the pem private key file. Please Check."
                sys.exit()

    # this function loads the public key. Opens the file and uses cryptography's serialization method to load the
    # PEM verison of the public key.
    def load_public_key(self):
        with open(self.pub_key_path, "rb") as key_file:
            try:
                return serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            except:
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

        print "-" * 50
        print "RSA ENCRYPTED : ", len(ciphertext)
        print "-" * 50
        return ciphertext

    # this function does rsa decryption given the cipher text.
    def rsa_decrypt(self, ciphertext):
        try:
            plaintext = self.private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                                          algorithm=hashes.SHA512(), label=None))
        except:
            print "Could not decrypt the data."
            sys.exit()

        print "-" * 50
        print "RSA DECRYPTION : ", len(plaintext)
        return plaintext

    # this function loads the public and private keys.
    def load_keys(self):
        self.public_key = self.load_public_key()
        self.private_key = self.load_private_key()


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

        print "---" * 50
        print "Doing checks on file : ", self.file_attachment_path
        self.do_file_checks()

        print "-" * 50
        print "Encrypting...."
        data = self.encrypt_data()

        print "-" * 50
        print "Writing to file : ", self.output_file
        with open(self.output_file, "w+") as f:
            f.write(base64.encodestring(data))

        print "*" * 50

    def decrypt_and_write(self):
        print "Decrypting...."
        alldata = open(self.plain_or_crypt_data_path, "r").read()
        alldata = base64.decodestring(alldata)
        data = self.decrypt_data(alldata)

        with open(self.output_file, "w+") as f:
            f.write(data)

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
        dictstring = json.dumps(self.fileInfo, encoding='utf-8')
        self.msg_data = self.msg_data + "\r\n\r\n" + dictstring

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

        # data = subprocess.Popen('openssl rsa -in {} -text -noout | grep " bit"'.format(self.priv_key_path), shell=True,
        #                         stdout=subprocess.PIPE).stdout.read()
        self.key_size = self.private_key.key_size
        if self.key_size == 1024:
            self.signature_length = 128
            self.aes_key = os.urandom(32)

        elif self.key_size == 2048:
            self.signature_length = 256
            self.aes_key = os.urandom(32)

        elif self.key_size == 4096:
            self.signature_length = 512
            self.aes_key = os.urandom(32)
        else:
            print "The file {} is not supported. Either you are using a weak key or something so strong that we don't " \
                  "really have a need for that or some other file instead of a key.".format(self.key_size)

            # sys.exit()


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
        pycrypter = pycrypt(options.encrypt, args[0], args[1], args[2], options.filepath)
        pycrypter.encrypt_and_write()
    elif options.decrypt:
        pycrypter = pycrypt(args[0], options.decrypt, args[1], args[2], options.filepath)
        pycrypter.decrypt_and_write()

    # print options, args
    # main()
