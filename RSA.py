#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 11 12:04:42 2020

@author: mdtamjidhossain
"""
#%%
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import binascii

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
#%%

keyPair = RSA.generate(3072)

pubKey = keyPair.publickey()
print(colored(255, 0, 0, "Public key:"))
print(f"(n={hex(pubKey.n)}, e={hex(pubKey.e)})" + '\n')

pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii')+ '\n')

print(colored(255, 0, 0, "Private key:"))
print(f"(n={hex(pubKey.n)}, d={hex(keyPair.d)})"+'\n')
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii')+'\n\n')
#%%
# Encryption

encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(plaintext.encode())
print(colored(255,0,0, "Encrypted:\n"), binascii.hexlify(encrypted), '\n')
#%%
# Decryption

decryptor = PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(encrypted)
print(colored(255,0,0,'Decrypted:\n'), decrypted, '\n\n')
#%%

end = time.time()
print(colored(255,0,0, 'Execution TIme: '), end - start)
#%%