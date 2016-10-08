#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json, base64
import ntpath
import os, sys, os.path
import subprocess
from optparse import OptionParser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class pycrypt:
    def __init__(self, pub_key_path, priv_key_path, plain_or_crypt_data_path, output_file, email_attachment):

        self.pub_key_path = pub_key_path
        self.email_id_example = "something@example.com"
        self.priv_key_path = priv_key_path
        self.plain_or_crypt_data_path = plain_or_crypt_data_path
        self.output_file = output_file
        self.verify_file_exists()
        self.get_key_length()
        self.load_keys()
        self.read_input_file()
        self.gcm_iv = 64
        self.file_attachment_path = email_attachment
        self.fileInfo = {}

    def read_input_file(self):

        self.msg_data = open(self.plain_or_crypt_data_path, "r").read()
        self.msg_data = bytes(bytearray(self.msg_data))

    def new_encrypt_data(self):
        self.setup_encrypter_env()
        encryptor = self.encrypter_cipher.encryptor()
        self.prepare_msgData_with_attachment()
        sig = self.generate_Signature(self.msg_data)

        encrypted_data = encryptor.update(sig + self.msg_data) + encryptor.finalize()
        tag = encryptor.tag

        print "-" * 50
        print "Encrypted Tag (GCM Auth) len: ", len(tag)
        print "-" * 50

        print "-" * 50
        print "Length of Encrypted Msg Data : ", len(encrypted_data)
        print "-" * 50

        rsaenc = self.RSA_encrypt(self.aes_key)

        print "-" * 50
        print "Signature len : ", len(sig)
        print "Signature : ", base64.encodestring(sig)
        print "IV len : ", len(self.iv)
        print "IV : ", base64.encodestring(self.iv)
        print "Tag len : ", len(tag)
        print "RSA Enc Length : ", len(rsaenc)
        print "AES Key : ", base64.encodestring(self.aes_key)
        print "-" * 50

        # RSA( IV + Tag ) + Encrypted Data
        return self.iv + tag + rsaenc + encrypted_data

        # self.decrypt_data(ct)

    def new_decrypt_data(self, alldata):

        iv = alldata[:self.gcm_iv]
        tag = alldata[self.gcm_iv: self.gcm_iv + 16]

        rsaenc = alldata[self.gcm_iv + 16:self.gcm_iv + 16 + self.signature_length]
        encrypted_data = alldata[self.gcm_iv + 16 + self.signature_length:]

        self.aes_key = self.RSA_decrypt(rsaenc)
        # print base64.encodestring(aes_key)

        self.setup_decrypter_env(tag, iv)
        decryptor = self.decrypter_cipher.decryptor()
        sig_msg = decryptor.update(encrypted_data) + decryptor.finalize()

        sig = sig_msg[:self.signature_length]
        msg = sig_msg[self.signature_length:]

        try:
            self.verify_signature(sig, msg)
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

    def setup_encrypter_env(self):

        self.aes_key = key = os.urandom(32)
        self.iv = os.urandom(self.gcm_iv)
        self.encrypter_cipher = Cipher(algorithms.AES(key), modes.GCM(self.iv), backend=default_backend())

    def setup_decrypter_env(self, tag, iv):
        self.decrypter_cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv, tag), backend=default_backend())

    def load_private_key(self):
        with open(self.priv_key_path, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    def load_public_key(self):
        with open(self.pub_key_path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    def RSA_encrypt(self, msg):

        ciphertext = self.public_key.encrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                               algorithm=hashes.SHA1(), label=None))
        print "-" * 50
        print "RSA ENCRYPTED : ", len(ciphertext)
        print "-" * 50
        return ciphertext

    def RSA_decrypt(self, ciphertext):
        plaintext = self.private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                                      algorithm=hashes.SHA1(), label=None))
        print "-" * 50
        print "RSA DECRYPTION : ", len(plaintext)
        return plaintext

    def load_keys(self):
        self.public_key = self.load_public_key()
        self.private_key = self.load_private_key()

    def generate_Signature(self, msg):
        signer = self.private_key.signer(
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        signer.update(msg)
        sig = signer.finalize()
        return sig

    def verify_signature(self, sig, msg):
        verifier = self.public_key.verifier(sig, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        verifier.update(msg)
        verifier.verify()

    def encrypt_and_write(self):

        print "---" * 50
        print "Doing checks on file : ", self.file_attachment_path
        self.do_file_checks()

        print "-" * 50
        print "Encrypting...."
        data = self.new_encrypt_data()

        print "-" * 50
        print "Writing to file : ", self.output_file
        with open(self.output_file, "w+") as f:
            f.write(data)

        print "*" * 50

    def decrypt_and_write(self):
        print "Decrypting...."
        alldata = open(self.plain_or_crypt_data_path, "r").read()

        data = self.new_decrypt_data(alldata)

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

    def prepare_msgData_with_attachment(self):
        dictstring = json.dumps(self.fileInfo)

        self.msg_data = self.msg_data + "\r\n\r\n" + dictstring

    def verify_file_exists(self):

        pass

    def get_key_length(self):

        data = subprocess.Popen('openssl rsa -in {} -text -noout | grep " bit"'.format(self.priv_key_path), shell=True,
                                stdout=subprocess.PIPE).stdout.read()
        if "2048" in data:
            self.key_size = 2048
            self.signature_length = 256
        elif "4096" in data:
            self.key_size = 4096
            self.signature_length = 512
        else:
            print "{} is not supported. Either you are using a weak key or something so strong that we don't " \
                  "really have a need for that.".format(data)

            # sys.exit()


def main():
    py = pycrypt("./public_key", "./private_key", "./data.txt", "./output")
    ct = py.encrypt_data()
    py.decrypt_data(ct)


if __name__ == "__main__":

    bashOptParser = OptionParser()
    bashOptParser.add_option("-d", dest="decrypt", help="Please enter file path to private key", default=False)
    bashOptParser.add_option("-e", dest='encrypt', help="Please enter file path to public key", default=False)
    bashOptParser.add_option("-f", dest='filepath', help="Please enter full file path to attach file", default=False)
    (options, args) = bashOptParser.parse_args()

    if options.encrypt:
        pycrypter = pycrypt(options.encrypt, args[0], args[1], args[2], options.filepath)
        pycrypter.encrypt_and_write()
    elif options.decrypt:
        pycrypter = pycrypt(args[0], options.decrypt, args[1], args[2], options.filepath)
        pycrypter.decrypt_and_write()

    print options, args
    # main()
