import os, sys, os.path
from optparse import OptionParser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class pycrypt:
    def __init__(self, pub_key_path, priv_key_path, plain_or_crypt_data, output_file):

        self.pub_key_path = pub_key_path
        self.priv_key_path = priv_key_path
        self.plain_or_crypt_data = plain_or_crypt_data
        self.output_file = output_file
        self.load_keys()
        self.msg_data = b"messagea secret messagea secret message"



    def encrypt_and_HMAC_data(self):
        self.setup_hmac_env()
        self.setup_encrypter_env()
        encryptor = self.encrypter_cipher.encryptor()
        ct = encryptor.update(self.msg_data) + encryptor.finalize()
        self.hmac.update(self.msg_data)
        bytess = self.hmac.finalize()

        print "bytess : ", bytess, len(bytess)
        print "-" * 30
        print "ct : ", ct, \
            "len", len(ct)

        msg = bytess+ct
        print len(msg)

        #return bytess + ct
        rsaenc = self.RSA_encrypt(msg)
        sig = self.generate_Signature(rsaenc)
        print "-"*30
        print "SIG : ",sig
        print "len : ", len(sig)
        print "-"*30


        return sig+rsaenc
        # self.decrypt_data(ct)



    def decrypt_data(self, alldata):
        self.setup_hmac_env()
        decryptor = self.encrypter_cipher.decryptor()
        sig = alldata[:256]
        print len(sig)

        encrypted_data = alldata[256:]
        ct = self.RSA_decrypt(encrypted_data)

        try:
            self.verify_signature(sig,encrypted_data)
            print "Signature verified."
        except:
            print "Signature verification failed."
            sys.exit()
        msg = decryptor.update(ct[32:]) + decryptor.finalize()
        try:
            self.verify_hmac(ct[:32], msg)
            print "HMAC VERIFIED"
        except:
            print "HMAC Signature verification failed."
            sys.exit()


    def verify_hmac(self, hmacSig, msg):
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



    def load_private_key(self):
        with open(self.priv_key_path, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())



    def load_public_key(self):
        with open(self.pub_key_path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read(), backend=default_backend())


    def RSA_encrypt(self,msg):

        ciphertext = self.public_key.encrypt(msg, padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA1()),algorithm = hashes.SHA1(),label = None))
        print "-"*30
        print "ciphertext : ",ciphertext
        print "-" * 30
        return ciphertext



    def RSA_decrypt(self,ciphertext):
        plaintext = self.private_key.decrypt(ciphertext, padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA1()), algorithm = hashes.SHA1(), label = None))
        print "-"*50
        print "RSA DECRYPT : " , plaintext , len(plaintext)
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


