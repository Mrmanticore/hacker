#pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import base64

keyPair = RSA.generate(2048)

pubKey = keyPair.publickey()
pubKeyPEM = pubKey.exportKey().decode('ascii')
print("Public key:")
print(pubKeyPEM)

privKeyPEM = keyPair.exportKey().decode('ascii')
print("Private key:")
print(privKeyPEM)

msg = b'Ismile Academy'
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)

encrypted_base64 = base64.b64encode(encrypted).decode('ascii')
print("Encrypted:", encrypted_base64)