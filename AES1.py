###Shoutout RSupreme4 Redacted###

#sender#
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import random
from Crypto import Random


data = 'secret data to transmit'.encode()




aes_key =get_random_bytes(16)
hmac_key =get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_CTR)
ciphertext = cipher.encrypt(data)
print(aes_key)
print(hmac_key)
#print("AES=",aes_key,'\n',"HMAC=",hmac_key)
hmac = HMAC.new(hmac_key, digestmod=SHA256)
tag = hmac.update(cipher.nonce + ciphertext).digest()
assert len(cipher.nonce) == 8

with open("encrypted.bin", "wb", ) as f:
    f.write(tag)
    f.write(cipher.nonce)
    f.write(ciphertext)


