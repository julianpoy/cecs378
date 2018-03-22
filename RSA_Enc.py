# -*- coding: utf-8 -*-
"""
Created on Thu Mar 15 12:26:58 2018

@author: SupaC
"""
import os
import sys
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


IVLength = 16
KeyLength = 32

def Myencrypt(plaintext, key):
  #Generates an iv of a given length
  iv = os.urandom(IVLength)
  #Creates an encryptor in the specified mode with the given ivs and key
  encryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv),
      backend=default_backend()
  ).encryptor()
  #Encrypts the plaintext
  ciphertext = encryptor.update(plaintext) + encryptor.finalize()
  #returns the values gotten
  return (iv, ciphertext, encryptor.tag)
    
def MyfileEncrypt(filepath):
  #Generates the key
  key = os.urandom(KeyLength)
  #Retrieves the file extension
  file_name, file_extension = os.path.splitext(filepath)

  #Opens the file specified at the file path in mode read binary
  with open(filepath, "rb") as binary_file:
    # Read the whole file at once
    data = binary_file.read()
    #Encrypts the file
    iv, ciphertext, tag = Myencrypt(
      data,
      key
    )
    #Returns the encrypted values
    return (ciphertext, tag, iv, key, file_extension)

def Mydecrypt(ciphertext, tag, iv, key):
  #Decrypts the ciphertext using the tag, iv and key
  decryptor = Cipher(
      algorithms.AES(key),
      modes.GCM(iv, tag),
      backend=default_backend()
  ).decryptor()
  #Returns the decrypted value
  return decryptor.update(ciphertext) + decryptor.finalize()

def MyfileDecrypt(filepath, RSA_Privatekey_filepath):
  #Retrieves the name of the file from the given file path without extension
  file_name = os.path.splitext(filepath)[0]
  
  #Opens file and reads the data as a json file format
  with open(filepath, 'r') as f:
  #Loads the json data format that was passed in from encryption
    data = json.load(f)
    #Decodes the data from base 64 value of the iv, ciphertext and tag
    iv = base64.b64decode(data['iv'])
    ciphertext = base64.b64decode(data['ciphertext_base64'])
    RSACipher = base64.b64decode(data['RSACipher'])
    tag = base64.b64decode(data['tag'])
    key = MyFileRSADecrypt(RSACipher, RSA_Privatekey_filepath)
    #Calls the mydecrypt method of the plaintext
    plaintext = Mydecrypt(ciphertext, tag, iv, key)
    #Creates the file name and extensino that was stored
    output_filename = file_name + data['file_extension']
    #Writes back to the file in binary specified by the file name
    f = open(output_filename, 'wb')
    f.write(plaintext)
    f.close()
    #returns the name of the decrypted file
    return output_filename
    
    
def MyRSAEncrypt(filepath, RSA_PublicKey_filepath):
  #Calls my file encrypt to encrypt the file
  ciphertext, tag, iv, key, file_extension = MyfileEncrypt(filepath)
  #checks for a password to access the rsa key pair
  #opens the rsa key filepath and reads the private key
  with open(RSA_PublicKey_filepath, 'rb') as key_file:
      public_key = serialization.load_ssh_public_key(
          key_file.read(),
#          password,
          backend=default_backend()
      )
      #closes the open file  
      key_file.close()
      #retireves the public key from the private retrieved (One thing I'm unsure of)
      #encrypts the key generated from myfileEncrypt with rsa public key	  
      RSACipher = public_key.encrypt(
        key,
        padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA1()),
          algorithm=hashes.SHA1(),
          label=None
          )
        )
      #returns the values
      return (RSACipher, ciphertext, tag, iv, file_extension)
         
def rsa_encrypt_file(filepath, RSA_PublicKey_filepath):
  #Retrieves the file name from the file path
  file_name = os.path.splitext(filepath)[0]
  #encrypts the file at the given filepath with rsa encryption
  RSACipher, ciphertext, tag, iv, file_extension = MyRSAEncrypt(filepath, RSA_PublicKey_filepath)
  #Creates an empty dictionary
  data = {}
  #Sets the dictionary with the corresponding values
  #The values are encoded in base64 so that there is no data loss across file translation
  data['ciphertext_base64'] = base64.b64encode(ciphertext).decode('utf-8')
  data['tag'] = base64.b64encode(tag).decode('utf-8')
  data['iv'] = base64.b64encode(iv).decode('utf-8')
  data['RSACipher'] = base64.b64encode(RSACipher).decode('utf-8')
  data['file_extension'] = file_extension
  
  #Creates the new name for the file using the original file name with a customized ext
  output_filename = file_name + '.rsamycrypt'
  
  #Creates a new file using the file name
  with open(output_filename, 'w') as outfile:
    #writes to the file using json format for the data dictionary to be retrieved during decryption
    outfile.write(json.dumps(data, outfile))
    #returns the key and the new file name
    return (output_filename)

def MyFileRSADecrypt(RSACipher, RSA_Privatekey_filepath):
  #checks for a password to access the rsa key pair
  password = input("Input your password for accessing your public key or leave blank if you have none")
  if password == "":
      password = None
  else:
      password = bytes(password, 'utf-8')
  #opens the rsa key filepath and reads the private key
  with open(RSA_Privatekey_filepath, 'rb') as key_file:
      private_key = serialization.load_pem_private_key(
          key_file.read(),
          password,
          backend=default_backend()
      )
      #closes the open file  
      key_file.close()
      #encrypts the key generated from myfileEncrypt with rsa public key	  
      key = private_key.decrypt(
        RSACipher,
        padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA1()),
          algorithm=hashes.SHA1(),
          label=None
          )
        )
      #returns the values
      return (key)
		   
    
## UI
if '--encrypt' in sys.argv and '--rsakeypath' in sys.argv:
  #takes in the file to be rsa encrypted
  filepath = sys.argv[sys.argv.index('--encrypt') + 1]
  #The rsa public key filepath
  RSA_PublicKey_filepath = sys.argv[sys.argv.index('--rsakeypath') + 1]
  #calls the rsa encryption method
  output_filename = rsa_encrypt_file(filepath, RSA_PublicKey_filepath)
  #os.remove(filepath)
  #prints out the key and the outputted file in base64 so no data is lost
  print("Output file: ", output_filename)
#Checks for --rsaencrypt and --rsakeypath and --rsacipher in the command line arguments
elif '--decrypt' in sys.argv and '--rsakeypath' in sys.argv:
  #takes in the file to be decrypted
  filepath = sys.argv[sys.argv.index('--decrypt') + 1]
  #takes in the file path to the private key
  RSA_Privatekey_filepath = sys.argv[sys.argv.index('--rsakeypath') + 1]
  #retrieves the new outputted file name
  output_filename = MyfileDecrypt(filepath, RSA_Privatekey_filepath)
  #removes the encrypted file
  os.remove(filepath)
  #displays the new outputted file
  print("Output file: ", output_filename)
#If the command was enacted wrong it will print out the correct way 
else:
  print("for rsa file encryption\n[--encrypt {filename} --rsakeypath {keyfilename}] or [--decrypt {filename} --rsakeypath (keyfilename)] is required")