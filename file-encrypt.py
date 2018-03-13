import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def Myencrypt(message, key):
  iv = os.urandom(16)

  encryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv),
      backend=default_backend()
  ).encryptor()

  ciphertext = encryptor.update(plaintext) + encryptor.finalize()

  return (iv, ciphertext, encryptor.tag)
    
def MyfileEncrypt(filepath):
  key = os.urandom(32)
  
  file_name = os.path.splitext(filepath)[0]
  file_extension = os.path.splitext(filepath)[1]

  with open(filepath, "rb") as binary_file:
    # Read the whole file at once
    data = binary_file.read()
    iv, ciphertext, tag = Myencrypt(
      data,
      key
    )
  
    f = open('encrypted_file.mycrypt', 'wb')
    f.write(ciphertext)
    f.close()
    
    return (ciphertext, iv, key, file_extension)

def Mydecrypt(ciphertext, iv, key):
  decryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv, tag),
      backend=default_backend()
  ).decryptor()

  return decryptor.update(ciphertext) + decryptor.finalize()

def MyfileDecrypt(filepath, key, iv, file_extension):
  with open(filepath, "rb") as binary_file:
    # Read the whole file at once
    ciphertext = binary_file.read()
    decrypted_body = decrypt(
      key,
      iv,
      ciphertext,
      tag
    )

    f = open('decypted_file' + file_extension, 'wb')
    f.write(decrypted_body)
    f.close()


  

# Based from for encrypt() and decrypt() methods taken from https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
