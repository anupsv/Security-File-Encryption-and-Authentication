import os,sys,argvemulator,cryptography,os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class pycrypt:

    def __init__(self,dest_key,sender_key,plain_or_crypt_data,output_file):

        self.dest_key = dest_key
        self.sender_key =sender_key
        self.plain_or_crypt_data = plain_or_crypt_data
        self.output_file = output_file




    def encrypt_and_HMAC_data(self):
        self.setup_hmac_env()
        self.setup_encrypter_env()
        encryptor = self.encrypter_cipher.encryptor()
        ct = encryptor.update(b"a secret messagea secret messagea secret messagea secret message") + encryptor.finalize()

        self.hmac.update(b"a secret messagea secret messagea secret messagea secret message")
        bytess= self.hmac.finalize()

        print "bytess : ",bytess,len(bytess)
        print "-"*30
        print "ct : ", ct,\
            "len",len(ct)

        print len(ct+bytess)
        return bytess+ct
        #self.decrypt_data(ct)

    def decrypt_data(self, ct):
        self.setup_hmac_env()
        decryptor = self.encrypter_cipher.decryptor()

        msg = decryptor.update(ct[32:]) + decryptor.finalize()

        try:
            self.verify_hmac(ct[:32], msg)
            print "HMAC VERIFIED"
        except:
            print "HMAC Signature verification failed."

    def verify_hmac(self,hmacSig,msg):
        self.hmac.update(msg)
        self.hmac.verify(hmacSig)


    def setup_encrypter_env(self):

        if not os.path.isfile("./aes_key"):
            key = os.urandom(32)
            open("./aes_key", "wb+").write(key)
        else:
            key = "".join(open("./aes_key", "rb").readlines())
        iv = os.urandom(16)
        self.encrypter_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


    def setup_hmac_env(self):


        if not os.path.isfile("./hmacKey"):
            self.hmac_key = os.urandom(256)
            open("./hmacKey", "wb+").write(self.hmac_key)
        else:
            self.hmac_key = "".join(open("./hmacKey", "rb").readlines())

        self.hmac = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())


py = pycrypt("","","","")
ct = py.encrypt_and_HMAC_data()
py.decrypt_data(ct)

