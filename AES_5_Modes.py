#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov  9 23:23:19 2020

@author: mdtamjidhossain
"""


#%%
# importing modules from library

from Cryptodome.Cipher import AES

import hashlib
import Padding
import binascii
import time

start = time.time()
#%%
# Text color function
def colored(r, g, b, text):
    return "\033[38;2;{};{};{}m{} \033[38;2;255;255;255m".format(r, g, b, text)

#%%
# encryption and decryption functions

def encrypt(blockList_byte, key, mode):
    cipherList_byte = []
    encobj = AES.new(key,mode)
    for block in blockList_byte:
        cipherList_byte.append(encobj.encrypt(block))
        
    return(cipherList_byte)

def decrypt(cipherList_byte,key, mode):
    plainTextList_byte = []
    encobj = AES.new(key,mode)
    for block in cipherList_byte:
        plainTextList_byte.append(encobj.decrypt(block))
    return(plainTextList_byte)

def encrypt2(blockList_byte, key, mode, iv):
    cipherList_byte = []
    encobj = AES.new(key,mode, iv)
    for block in blockList_byte:
        cipherList_byte.append(encobj.encrypt(block))
        
    return(cipherList_byte)

def decrypt2(cipherList_byte,key, mode, iv):
    plainTextList_byte = []
    encobj = AES.new(key,mode,iv)
    for block in cipherList_byte:
        plainTextList_byte.append(encobj.decrypt(block))
    return(plainTextList_byte)

def encrypt3(blockList_byte, key, mode):
    cipherList_byte = []
    encobj = AES.new(key,AES.MODE_CTR)
    nonce = encobj.nonce
    for block in blockList_byte:
        cipherList_byte.append(encobj.encrypt(block))
        
    return(cipherList_byte, nonce)

def decrypt3(cipherList_byte,key, mode, nonce):
    plainTextList_byte = []
    encobj = AES.new(key,mode, nonce =  nonce)
    for block in cipherList_byte:
        plainTextList_byte.append(encobj.decrypt(block))
    return(plainTextList_byte)

#%%

def plainTextToByte(plaintext):
    plaintext = Padding.appendPadding(plaintext,blocksize=Padding.AES_blocksize,mode=0)
    plaintext_byte = plaintext.encode('utf-8')
    blockList_byte = [plaintext_byte[i:i+16] for i in range(0, len(plaintext_byte), 16)]
    return blockList_byte

def byteToHexBlock(blockList_byte):
    blockList_hex = []
    for byte in blockList_byte:
        blockList_hex.append(binascii.hexlify(byte).decode())
    return blockList_hex

#%%
# importing message from a file
    
# plainTextLoc= '/Users/mdtamjidhossain/Fall-2020/Courses/CS654/Project/plainText.txt'
plainTextLoc= '/Users/mdtamjidhossain/Fall-2020/Courses/CS654/Project/plainTextWithError.txt'
with open(plainTextLoc, 'r') as file:
    data = file.read().replace('\n', '')

message = data

plaintext = message
#%%

#1. With AES as the encryption / decryption algorithm, generate your own key.

# from Crypto.Random import get_random_bytes
# key = get_random_bytes(32) # 32 bytes * 8 = 256 bits
# print(colored(255,0,0,"key (32 bytes):\t")+ str(key))

password ='cs654pass2020'
ival=12

key = hashlib.sha256(password.encode()).digest()

iv= hex(ival)[2:8].zfill(16)


print(colored(255, 0, 0, 'AES Key (32 bytes or 256 bits):'))
print(str(key) + '\n')

print(colored(255, 0, 0, 'AES initialization vector (IV) :'))
print(str(iv) + '\n')
    
#%%
blockList_byte = []
blockList_hex = []

#%%
# encrypt and decrypt using ECB, CBC, CFB, OFB, CTR
print(colored(255, 0, 0, 'Original Message (string):'))
print(str(data) + '\n')

blockList_byte = plainTextToByte(data)    
print(colored(255, 0, 0, 'Original Message after padding (bytes):'))
print(str(blockList_byte) + '\n')

blockList_hex = byteToHexBlock(blockList_byte)
print(colored(255, 0, 0, 'Original Message after padding (hex):'))
print(str(blockList_hex) + '\n')
print(colored(255, 0, 0, 'Encrypt and Decrypt using ECB, CBC, CFB, OFB, CTR :'))

#--------------------ECB starts---------------------------------------------
cipherList_byte = encrypt(blockList_byte,key, AES.MODE_ECB)
blockList_hex = byteToHexBlock(cipherList_byte)
print (colored(0, 255, 0, "  CipherBlock (ECB):\t")+str(blockList_hex))
print (colored(0, 255, 0, "  Ciphertext (ECB):\t")+ str(''.join(blockList_hex)))


plainTextList_byte = decrypt(cipherList_byte,key,AES.MODE_ECB)
plainTextList_str = []
for plaintext in plainTextList_byte:
    try:
        plainTextList_str.append(Padding.removePadding(plaintext.decode(),mode=0))
    except:
        plainTextList_str.append(plaintext.decode())
print (colored(0, 255, 0, "  PlaintextBlock (ECB):\t")+str(plainTextList_str))
print (colored(0, 255, 0, "  Plaintext (ECB):\t")+str(''.join(plainTextList_str))+ '\n')
#--------------------ECB ends---------------------------------------------

#--------------------CBC starts---------------------------------------------
cipherList_byte = encrypt2(blockList_byte,key, AES.MODE_CBC, iv.encode())
blockList_hex = byteToHexBlock(cipherList_byte)
print (colored(235, 204, 52, "  CipherBlock (CBC):\t   ")+str(blockList_hex))
print (colored(235, 204, 52, "  Ciphertext (CBC):\t   ")+ str(''.join(blockList_hex)))


plainTextList_byte = decrypt2(cipherList_byte,key,AES.MODE_CBC,iv.encode())
plainTextList_str = []
for plaintext in plainTextList_byte:
    try:
        plainTextList_str.append(Padding.removePadding(plaintext.decode(),mode=0))
    except:
        plainTextList_str.append(plaintext.decode())
print (colored(235, 204, 52, "  PlaintextBlock (CBC):  ")+str(plainTextList_str))
print (colored(235, 204, 52, "  Plaintext (CBC):\t   ")+str(''.join(plainTextList_str))+ '\n')
#--------------------CBC ends---------------------------------------------

#--------------------CFB starts---------------------------------------------
cipherList_byte = encrypt2(blockList_byte,key, AES.MODE_CFB, iv.encode())
blockList_hex = byteToHexBlock(cipherList_byte)
print (colored(52, 201, 235, "  CipherBlock (CFB):\t   ")+str(blockList_hex))
print (colored(52, 201, 235, "  Ciphertext (CFB):\t   ")+ str(''.join(blockList_hex)))

plainTextList_byte = decrypt2(cipherList_byte,key,AES.MODE_CFB,iv.encode())
plainTextList_str = []
for plaintext in plainTextList_byte:
    try:
        plainTextList_str.append(Padding.removePadding(plaintext.decode(),mode=0))
    except:
        plainTextList_str.append(plaintext.decode())
print (colored(52, 201, 235, "  PlaintextBlock (CFB):  ")+str(plainTextList_str))
print (colored(52, 201, 235, "  Plaintext (CFB):\t   ")+str(''.join(plainTextList_str)) + '\n')
#--------------------CFB ends---------------------------------------------

#--------------------OFB starts---------------------------------------------
cipherList_byte = encrypt2(blockList_byte,key, AES.MODE_OFB, iv.encode())
blockList_hex = byteToHexBlock(cipherList_byte)
print (colored(183, 52, 235, "  CipherBlock (OFB):\t   ")+str(blockList_hex))
print (colored(183, 52, 235, "  Ciphertext (OFB):\t   ")+ str(''.join(blockList_hex)))


plainTextList_byte = decrypt2(cipherList_byte,key,AES.MODE_OFB,iv.encode())
plainTextList_str = []
for plaintext in plainTextList_byte:
    try:
        plainTextList_str.append(Padding.removePadding(plaintext.decode(),mode=0))
    except:
        plainTextList_str.append(plaintext.decode())
print (colored(183, 52, 235, "  PlaintextBlock (OFB):  ")+str(plainTextList_str))
print (colored(183, 52, 235, "  Plaintext (OFB):\t   ")+str(''.join(plainTextList_str))+ '\n')
#--------------------OFB ends---------------------------------------------


#--------------------CTR starts---------------------------------------------
cipherList_byte, nonce = encrypt3(blockList_byte,key, AES.MODE_CTR)
blockList_hex = byteToHexBlock(cipherList_byte)
print (colored(235, 125, 52, "  CipherBlock (CTR):\t   ")+str(blockList_hex))
print (colored(235, 125, 52, "  Ciphertext (CTR):\t   ")+ str(''.join(blockList_hex)))


plainTextList_byte = decrypt3(cipherList_byte,key,AES.MODE_CTR,nonce)
plainTextList_str = []
for plaintext in plainTextList_byte:
    try:
        plainTextList_str.append(Padding.removePadding(plaintext.decode(),mode=0))
    except:
        plainTextList_str.append(plaintext.decode())
print (colored(235, 125, 52, "  PlaintextBlock (CTR):  ")+str(plainTextList_str))
print (colored(235, 125, 52, "  Plaintext (CTR):\t   ")+str(''.join(plainTextList_str))+ '\n')
nonce = ''
#--------------------CTR ends---------------------------------------------


#%%
end = time.time()
print(end - start)