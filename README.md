# CECS 378

## Encrypting and decrypting files with basic GCM

file-encrypt.py includes the first part of the file encryption lab. You can encrypt a file with the following command:

`python3 file-encrypt.py --encrypt {filename}`

You can decrypt an encrypted file (.mycrypt filetype) with the following command:

`python3 file-encrypt.py --decrypt {filename} --key {key}`

## Encrypting and decrypting files using GCM and RSA

file-encrypt-rsa.py includes the second part of the file encryption lab. You can encrypt a file using RSA with the following command:

`python3 file-encrypt-rsa.py --encrypt {filename}`--key {rsa public key path}

You can decrypt an encrypted file (.mycrypt filetype) with the following command:

`python3 file-encrypt-rsa.py --decrypt {filename} --key {rsa private key path}

Note that this will NOT return the raw key to you, unlike with basic GCM. The raw key is encrypted with RSA and is then stored within the file.

Additionally, note that several of the methods have been adapted to support RSA. file-encrypt-rsa.py and file-encrypt.py are not backwards compatible.
