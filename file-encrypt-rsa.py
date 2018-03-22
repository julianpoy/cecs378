import os
import sys
import json
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def Myencrypt(plaintext, key):
  iv_length = 16
  iv = os.urandom(iv_length)

  encryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv),
      backend=default_backend()
  ).encryptor()

  ciphertext = encryptor.update(plaintext) + encryptor.finalize()

  return (iv, ciphertext, encryptor.tag)
    
def MyfileEncrypt(filepath):
  key_length = 32
  key = os.urandom(key_length)
  
  file_name = os.path.splitext(filepath)[0]
  file_extension = os.path.splitext(filepath)[1]

  with open(filepath, "rb") as binary_file:
    # Read the whole file at once
    data = binary_file.read()
    iv, ciphertext, tag = Myencrypt(
      data,
      key
    )
    
    return (ciphertext, tag, iv, key, file_extension)

def Mydecrypt(ciphertext, tag, iv, key):
  decryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv, tag),
      backend=default_backend()
  ).decryptor()

  return decryptor.update(ciphertext) + decryptor.finalize()

# Takes a key cipher and a pem filepath
# Returns the decrypted key
def MyRSADecrypt(key_cipher, pem_filepath):
  # Written in collaboration with @ChrisMeyer7088
  password = input("Enter PEM Password: ")
  if password == '':
    password = None
  else:
    password = bytes(password, 'utf-8')
    
  with open(pem_filepath, 'rb') as pem_file:
    pem = serialization.load_pem_private_key(
      pem_file.read(),
      password,
      backend=default_backend()
    )
    pem_file.close()
    key = pem.decrypt(
      key_cipher,
      padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
      )
    )

    return key

def MyfileDecrypt(filepath, rsa_pem_path):
  file_name = os.path.splitext(filepath)[0]
  
  with open(filepath, 'r') as f:
    data = json.load(f)
    
    iv = base64.b64decode(data['iv'])
    ciphertext = base64.b64decode(data['ciphertext_base64'])
    tag = base64.b64decode(data['tag'])
    
    key_encby_rsa = base64.b64decode(data['RSACipher'])
    key = MyRSADecrypt(key_encby_rsa, rsa_pem_path)
  
    plaintext = Mydecrypt(ciphertext, tag, iv, key)
    
    output_filename = file_name + data['file_extension']
    
    f = open(output_filename, 'wb')
    f.write(plaintext)
    f.close()
    
    return output_filename
    
def MyRSAEncrypt(filepath, rsa_pub_path):
  ciphertext, tag, iv, key, file_extension = MyfileEncrypt(filepath)
  
  # Written in collaboration with @ChrisMeyer7088
  with open(rsa_pub_path, 'rb') as pub_file:
    pub = serialization.load_ssh_public_key(
      pub_file.read(),
      backend=default_backend()
    )
    pub_file.close()
    key_encby_rsa = pub.encrypt(
      key,
      padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
      )
    )
    
    return (ciphertext, tag, iv, key_encby_rsa, file_extension)
  

def encrypt_file(filepath, rsa_pub_path):
  file_name = os.path.splitext(filepath)[0]
  
  ciphertext, tag, iv, key_encby_rsa, file_extension = MyRSAEncrypt(filepath, rsa_pub_path)
  
  data = {}
  
  data['ciphertext_base64'] = base64.b64encode(ciphertext).decode('utf-8')
  data['tag'] = base64.b64encode(tag).decode('utf-8')
  data['iv'] = base64.b64encode(iv).decode('utf-8')
  data['file_extension'] = file_extension
  
   # Using 'RSACipher' as key value to ensure compatibility with @ChrisMeyer7088's version
  data['RSACipher'] = base64.b64encode(key_encby_rsa).decode('utf-8')
  
  output_filename = file_name + '.mycrypt'
  
  with open(output_filename, 'w') as outfile:  
    outfile.write(json.dumps(data))
  
    return output_filename

## UI
if '--encrypt' in sys.argv and '--key' in sys.argv:
  filepath = sys.argv[sys.argv.index('--encrypt') + 1]
  keypath = sys.argv[sys.argv.index('--key') + 1]
  output_filename = encrypt_file(filepath, keypath)
  
  os.remove(filepath)
  
  print("Output file: ", output_filename)
elif '--decrypt' in sys.argv and '--key' in sys.argv:
  filepath = sys.argv[sys.argv.index('--decrypt') + 1]
  keypath = sys.argv[sys.argv.index('--key') + 1]
  
  output_filename = MyfileDecrypt(filepath, keypath)
  
  os.remove(filepath)
  
  print("Output file: ", output_filename)
  
else:
  print("[--encrypt {filename} --key {pub_keypath}] or [--decrypt {filename} --key {pem_keypath}] is required")


# Based from for encrypt() and decrypt() methods taken from https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
