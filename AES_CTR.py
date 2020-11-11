#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov  9 23:23:19 2020

@author: mdtamjidhossain
"""

import json
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import hashlib

import time
#%%

start = time.time()

#%%

# Text color function
def colored(r, g, b, text):
    return "\033[38;2;{};{};{}m{} \033[38;2;255;255;255m".format(r, g, b, text)

#%%
# importing message from a file
    
plainTextLoc= '/Users/mdtamjidhossain/Fall-2020/Courses/CS654/Project/plainText_long.txt'
# plainTextLoc= '/Users/mdtamjidhossain/Fall-2020/Courses/CS654/Project/plainTextWithError.txt'
with open(plainTextLoc, 'r') as file:
    data = file.read().replace('\n', '')

message = data

plaintext = message
print(colored(255, 0, 0, 'Original Message (string):\n'), data, '\n')

#%%
# generating 32-bytes AES key

password ='cs654pass2020'

key = hashlib.sha256(password.encode()).digest()
print(colored(255, 0, 0, 'AES Key (32 bytes or 256 bits):\n'), key, '\n')
#%%
# Encryption using CTR mode

cipher = AES.new(key, AES.MODE_CTR)
ct_bytes = cipher.encrypt(plaintext.encode())
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'nonce':nonce, 'ciphertext':ct})
print(colored(255,0,0,'Encrypted text:\n'),ct, '\n')
#%%
# Decryption using CTR mode

try:
    b64 = json.loads(result)
    nonce = b64decode(b64['nonce'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    print(colored(255,0,0,"Decrypted text:\n"), pt.decode(), '\n\n')
except(ValueError, KeyError):
    print("Incorrect decryption")
#%%

end = time.time()
print(colored(255,0,0, 'Execution TIme: '), end - start)
#%%