import time
from Crypto import Random
from base64 import b64encode,b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

import aes

def test(plaintext,key):
    my_res,res = [],[]
    print("##############################")
    print("TEST ECB")
    print("##############################")
    start = time.time()
    enc=aes.aes128_ecb_encrypt(plaintext,key)
    dec=aes.aes128_ecb_decrypt(enc,key)
    end = time.time()
    my_e_time=end-start
    my_correct = dec == plaintext
    start = time.time()
    my_res.append(my_e_time)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext= cipher.encrypt(pad((plaintext),AES.block_size))
    cipher = AES.new(key, AES.MODE_ECB)
    plain = unpad(cipher.decrypt(ciphertext),AES.block_size)
    end = time.time()
    e_time = end-start
    res.append(e_time)
    correct= plaintext == plain
    print("My aes is "+str(my_correct))
    print("Pycriptodome aes is "+str(correct))
    print("My elapsed time is "+str(my_e_time))
    print("Pycriptodome elapsed time is "+str(e_time))
    print("Pycryptodome library is "+str(my_e_time/e_time) + " times faster than my aes" )
    print("##############################")
    print("TEST CBC")
    print("##############################")
    random = Random.new()
    iv = random.read(16)
    start = time.time()
    enc=aes.aes128_cbc_encrypt(plaintext,key,iv)
    dec=aes.aes128_cbc_decrypt(enc,key,iv)
    end = time.time()
    my_e_time=end-start
    my_correct = dec == plaintext
    start = time.time()
    my_res.append(my_e_time)

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv_ = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC,b64decode(iv_))
    pt = unpad(cipher.decrypt(b64decode(ct)), AES.block_size)
    end = time.time()
    e_time = end-start
    res.append(e_time)
    correct= plaintext == pt
    print("My aes is "+str(my_correct))
    print("Pycriptodome aes is "+str(correct))
    print("My elapsed time is "+str(my_e_time))
    print("Pycriptodome elapsed time is "+str(e_time))
    print("Pycryptodome library is "+str((my_e_time/e_time)) + " times faster than my aes" )
    print("##############################")
    print("TEST CFB")
    print("##############################")
    
    start = time.time()
    enc=aes.aes128_cfb_encrypt(plaintext,key,iv)
    dec=aes.aes128_cfb_decrypt(enc,key,iv)
    end = time.time()
    my_e_time=end-start
    my_correct = dec == plaintext
    start = time.time()
    my_res.append(my_e_time)

    cipher = AES.new(key, AES.MODE_CFB)
    ct_bytes = cipher.encrypt(pad((plaintext),AES.block_size))
    iv_ = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CFB,b64decode(iv_))
    pt = unpad(cipher.decrypt(b64decode(ct)),AES.block_size)
    end = time.time()
    res.append(e_time)
    e_time = end-start
    correct= plaintext == pt
    print("My aes is "+str(my_correct))
    print("Pycriptodome aes is "+str(correct))
    print("My elapsed time is "+str(my_e_time))
    print("Pycriptodome elapsed time is "+str(e_time))
    print("Pycryptodome library is "+str((my_e_time/e_time)) + " times faster than my aes" )
    print("##############################")
    print("TEST OFB")
    print("##############################")
    
    start = time.time()
    enc=aes.aes128_ofb_encrypt(plaintext,key,iv)
    dec=aes.aes128_ofb_decrypt(enc,key,iv)
    end = time.time()
    my_e_time=end-start
    my_correct = dec == plaintext
    start = time.time()
    my_res.append(my_e_time)

    cipher = AES.new(key, AES.MODE_OFB)
    ct_bytes = cipher.encrypt(pad(plaintext,AES.block_size))
    iv_ = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_OFB,b64decode(iv_))
    pt = unpad(cipher.decrypt(b64decode(ct)),AES.block_size)
    end = time.time()
    e_time = end-start
    res.append(e_time)
    correct= plaintext == pt
    print("My aes is "+str(my_correct))
    print("Pycriptodome aes is "+str(correct))
    print("My elapsed time is "+str(my_e_time))
    print("Pycriptodome elapsed time is "+str(e_time))
    print("Pycryptodome library is "+str((my_e_time/e_time)) + " times faster than my aes" )
    print("##############################")
    print("TEST CTR")
    print("##############################")
    
    start = time.time()
    nonce= iv
    enc=aes.aes128_ctr_encrypt(plaintext,key,nonce)
    dec=aes.aes128_ctr_decrypt(enc,key,nonce)
    end = time.time()
    my_e_time=end-start
    my_correct = dec == plaintext
    start = time.time()
    my_res.append(my_e_time)

    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(pad(plaintext,AES.block_size))
    nonce_ = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CTR,nonce=b64decode(nonce_))
    pt = unpad(cipher.decrypt(b64decode(ct)),AES.block_size)
    end = time.time()
    e_time = end-start
    res.append(e_time)
    correct= plaintext == pt
    print("My aes is "+str(my_correct))
    print("Pycriptodome aes is "+str(correct))
    print("My elapsed time is "+str(my_e_time))
    print("Pycriptodome elapsed time is "+str(e_time))
    print("Pycryptodome library is "+str((my_e_time/e_time)) + " times faster than my aes" )
    print("##############################")
    return my_res,res

print("128 bit test")
my128,c128=test(b'a'*16,b'k'*16)
print("1kB test")
my1k,c1k=test(b'a'*1000,b'k'*16)
print("100kB test")
my100k,c100k=test(b'a'*100000,b'k'*16)
print("10MB test")
my10M,c10M=test(b'a'*10000000,b'k'*16)

import numpy as np
import matplotlib.pyplot as plt
data = [my128,c128]

X = np.arange(5)


fig,ax = plt.subplots(1, 3)

ax[0].bar(X, my1k, 0.35, label='myaes')
ax[0].bar(X + 0.35, c1k, 0.35,label='pycrypto')
ax[0].set_xticks(X + 0.35 / 2, ('ECB', 'CBC', 'CFB', 'OFB', 'CTR'))
ax[0].legend(loc='best')
ax[0].set_title("1k test (lower is better)")
ax[1].bar(X, my100k, 0.35, label='myaes')
ax[1].bar(X + 0.35, c100k, 0.35,label='pycrypto')
ax[1].set_xticks(X + 0.35 / 2, ('ECB', 'CBC', 'CFB', 'OFB', 'CTR'))
ax[1].legend(loc='best')
ax[1].set_title("100k test (lower is better)")
ax[2].bar(X, my10M, 0.35, label='myaes')
ax[2].bar(X + 0.35, c10M, 0.35,label='pycrypto')
ax[2].set_xticks(X + 0.35 / 2, ('ECB', 'CBC', 'CFB', 'OFB', 'CTR'))
ax[2].legend(loc='best')
ax[2].set_title("10M test (lower is better)")

#plt.setp(ax, xticks=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'])

plt.show()