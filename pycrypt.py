import os, sys, os.path
from optparse import OptionParser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class pycrypt:
    def __init__(self, pub_key_path, priv_key_path, plain_or_crypt_data_path, output_file):

        self.pub_key_path = pub_key_path
        self.priv_key_path = priv_key_path
        self.plain_or_crypt_data_path = plain_or_crypt_data_path
        self.output_file = output_file
        self.load_keys()
        #self.msg_data = b"messagea secret messagea secret message"
        self.read_input_file()
        self.gcm_iv = 64

    def read_input_file(self):

        self.msg_data = open(self.plain_or_crypt_data_path, "r").read()
        self.msg_data = bytes(bytearray(self.msg_data))
        print "self.msg_data : ", type(self.msg_data), len(self.msg_data)



    def encrypt_and_HMAC_data(self):
        self.setup_encrypter_env()
        encryptor = self.encrypter_cipher.encryptor()
        ct = encryptor.update(self.msg_data) + encryptor.finalize()
        tag = encryptor.tag

        print "-" * 50
        print "Encrypted Tag (GCM Auth) len: ", len(tag)

        print "-" * 50
        print "Length of Encrypted Msg Data : ", len(ct)

        msg = tag+ct
        print len(msg)

        #return bytess + ct
        rsaenc = self.RSA_encrypt(msg)
        sig = self.generate_Signature(rsaenc)
        print "-" * 50
        #print "SIG : ",sig
        print "Signature len : ", len(sig)
        print "IV len : " , len(self.iv)
        print "Tag len : ", len(tag)
        print "-" * 50


        return self.iv+sig+rsaenc
        # self.decrypt_data(ct)



    def decrypt_data(self, alldata):

        iv = alldata[:self.gcm_iv]
        sig = alldata[self.gcm_iv:256+self.gcm_iv]
        print len(sig)

        encrypted_data = alldata[256+self.gcm_iv:]
        ct = self.RSA_decrypt(encrypted_data)
        tag = ct[:16]

        print "TAG LEN : ", len(tag)
        print "IV LEN : ", len(iv)

        try:
            self.verify_signature(sig,encrypted_data)
            print "Signature verified."
        except:
            print "Signature verification failed."
            sys.exit()

        self.setup_decrypter_env(tag,iv)
        decryptor = self.decrypter_cipher.decryptor()
        msg = decryptor.update(ct[16:]) + decryptor.finalize()
        print "-"*50
        print msg
        print "-" * 50
        with open(self.output_file,"w+") as f:
            f.write(msg)


    def setup_encrypter_env(self):

        if not os.path.isfile("./aes_key"):
            key = os.urandom(32)
            open("./aes_key", "wb+").write(key)
        else:
            key = "".join(open("./aes_key", "rb").readlines())
        self.iv = os.urandom(self.gcm_iv)
        self.encrypter_cipher = Cipher(algorithms.AES(key), modes.GCM(self.iv), backend=default_backend())


    def setup_decrypter_env(self,tag,iv):

        if not os.path.isfile("./aes_key"):
            key = os.urandom(32)
            open("./aes_key", "wb+").write(key)
        else:
            key = "".join(open("./aes_key", "rb").readlines())

        self.decrypter_cipher = Cipher(algorithms.AES(key), modes.GCM(iv,tag), backend=default_backend())


    def load_private_key(self):
        with open(self.priv_key_path, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())



    def load_public_key(self):
        with open(self.pub_key_path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read(), backend=default_backend())


    def RSA_encrypt(self,msg):

        ciphertext = self.public_key.encrypt(msg, padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA1()),algorithm = hashes.SHA1(),label = None))
        print "-" * 50
        print "RSA ENCRYPTED : ",len(ciphertext)
        print "-" * 50
        return ciphertext



    def RSA_decrypt(self,ciphertext):
        plaintext = self.private_key.decrypt(ciphertext, padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA1()), algorithm = hashes.SHA1(), label = None))
        print "-"*50
        print "RSA DECRYPTION : " , len(plaintext)
        return plaintext



    def load_keys(self):
        self.public_key = self.load_public_key()
        self.private_key = self.load_private_key()

    def generate_Signature(self,msg):
        signer = self.private_key.signer(padding.PSS(mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())
        signer.update(msg)
        sig = signer.finalize()
        return sig

    def verify_signature(self, sig,msg):
        verifier = self.public_key.verifier(sig, padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())
        verifier.update(msg)
        verifier.verify()


    def encrypt_and_write(self):
        self.encrypt_and_HMAC_data()


def main():
    py = pycrypt("./public_key", "./private_key", "./data.txt", "./output")
    ct = py.encrypt_and_HMAC_data()
    py.decrypt_data(ct)


if __name__ == "__main__":
    main()
    sys.exit()
    bashOptParser = OptionParser()
    bashOptParser.add_option("-d", dest="decrypt", help="Please enter file path to private key", default=False)
    bashOptParser.add_option("-e", dest='encrypt', help="Please enter file path to public key", default=False)
    (options, args) = bashOptParser.parse_args()
    if options["encrypt"]:
        pycrypter = pycrypt(options["encrypt"], args[0], args[1], args[2])
        pycrypter.encrypt_and_write()
    elif options["decrypt"]:
        pycrypter = pycrypt(args[0],options["encrypt"], args[1], args[2])

    print options, args
    #main()


