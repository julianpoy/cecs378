import os
import sys
import json
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def Myencrypt(plaintext, key):
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
    
    return (ciphertext, iv, key, file_extension)

def Mydecrypt(ciphertext, iv, key):
  decryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv, tag),
      backend=default_backend()
  ).decryptor()

  return decryptor.update(ciphertext) + decryptor.finalize()

def MyfileDecrypt(filepath, key):
  with open(filepath, 'r') as f:
    data = json.load(f)
    
    iv = base64.b64decode(data['iv'])
    ciphertext = base64.b64decode(data['ciphertext_base64'])
  
    plaintext = Mydecrypt(ciphertext, iv, key)
    
    output_filename = 'decypted_file' + data['file_extension']
    
    f = open(output_filename, 'wb')
    f.write(plaintext)
    f.close()
    
    return output_filename

def encrypt_file(filepath):
  ciphertext, iv, key, file_extension = MyfileEncrypt(filepath)
  
  data = {}
  
  data['ciphertext_base64'] = base64.b64encode(ciphertext).decode('utf-8')
  data['iv'] = base64.b64encode(iv).decode('utf-8')
  data['file_extension'] = file_extension
  
  output_filename = 'encrypted_file.mycrypt'
  
  with open(output_filename, 'w') as outfile:  
    outfile.write(json.dumps(data, outfile))
  
    return (key, output_filename)
  
def decrypt_file(filepath, key):
  MyfileDecrypt(filepath, key)

## UI
if '--encrypt' in sys.argv:
  key, output_filename = encrypt_file(sys.argv[sys.argv.index('--encrypt') + 1])
  
  print("Key: ", base64.b64encode(key).decode('utf-8'))
  print("Output file: ", output_filename)
elif '--decrypt' in sys.argv and '--key' in sys.argv:
  output_filename = decrypt_file(sys.argv[sys.argv.index('--decrypt') + 1], base64.b64decode(sys.argv[sys.argv.index('--key') + 1]))
  
  print("Output file: ", output_filename)
  
else:
  print("[--encrypt {filename}] or [--decrypt {filename} --key {key}] is required")


# Based from for encrypt() and decrypt() methods taken from https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
