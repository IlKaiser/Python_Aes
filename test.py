import time
from Crypto import Random
from base64 import b64encode,b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

import aes

def test(plaintext,key):
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

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext= cipher.encrypt(pad((plaintext),AES.block_size))
    cipher = AES.new(key, AES.MODE_ECB)
    plain = unpad(cipher.decrypt(ciphertext),AES.block_size)
    end = time.time()
    e_time = end-start
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

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv_ = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC,b64decode(iv_))
    pt = unpad(cipher.decrypt(b64decode(ct)), AES.block_size)
    end = time.time()
    e_time = end-start
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

    cipher = AES.new(key, AES.MODE_CFB)
    ct_bytes = cipher.encrypt(pad((plaintext),AES.block_size))
    iv_ = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CFB,b64decode(iv_))
    pt = unpad(cipher.decrypt(b64decode(ct)),AES.block_size)
    end = time.time()
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

    cipher = AES.new(key, AES.MODE_OFB)
    ct_bytes = cipher.encrypt(pad(plaintext,AES.block_size))
    iv_ = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_OFB,b64decode(iv_))
    pt = unpad(cipher.decrypt(b64decode(ct)),AES.block_size)
    end = time.time()
    e_time = end-start
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

    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(pad(plaintext,AES.block_size))
    nonce_ = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CTR,nonce=b64decode(nonce_))
    pt = unpad(cipher.decrypt(b64decode(ct)),AES.block_size)
    end = time.time()
    e_time = end-start
    correct= plaintext == pt
    print("My aes is "+str(my_correct))
    print("Pycriptodome aes is "+str(correct))
    print("My elapsed time is "+str(my_e_time))
    print("Pycriptodome elapsed time is "+str(e_time))
    print("Pycryptodome library is "+str((my_e_time/e_time)) + " times faster than my aes" )
    print("##############################")

print("128 bit test")
test(b'a'*16,b'k'*16)
print("1k bit test")
test(b'a'*160,b'k'*16)
print("100k bit test")
test(b'a'*1600,b'k'*16)
print("10M bit test")
test(b'a'*160000,b'k'*16)