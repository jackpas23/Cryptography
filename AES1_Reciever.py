from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import sys
aes_key=b'A\x83\x89\x14n\x0c\x1c\xbd\xf5\x1d\xe8\xdb\xdemmm'
hmac_key=b"\x85\xb7\x9d\\u\x85\xcd\xa3\xa3L'&O\xf8x\xc6"
with open("encrypted.bin", "rb") as f:
    tag = f.read(32)
    nonce = f.read(8)
    ciphertext = f.read()
    
try:
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(nonce + ciphertext).verify(tag)
except ValueError:
    print("The message was modified!")
    sys.exit(1)

    

cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)

message = cipher.decrypt(ciphertext)

print("Message:", message.decode())