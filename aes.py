"""

    Python AES-128 Implementation

"""
# Import Tables
from tables import s_box,inv_s_box,rc

#128 bit plaintext and key
plaintext=b'a'*16
key=b'keyy'*4
## PKCS#7 padding
def pad(text):
    check=len(text) % 16
    padding_len=16-check
    return text+[padding_len]*padding_len

## PCKS# remove padding
def remove_padding(text):
    padding_len=text[-1]
    #pseudo oracle
    assert all(e==padding_len for e in text[-padding_len:-1])
    return text[0:-padding_len]

## From plaintext to 16 byte block for encrypt
def text2blocks(text,add_padding=False):
    blocks=[]
    if add_padding:
        text=pad(text)
    for i in range (0,len(text),16):
       blocks.append(text[i:i+16])
    return blocks

## From blocks to text
flatten = lambda t: [item for sublist in t for item in sublist]
def blocks2text(blocks,padding=False):
    to_ret=flatten(blocks)
    if padding:
        to_ret=remove_padding(to_ret)
    return to_ret
    
## From 16 byte block to matrix
def block2matrix(block):
    assert len(block) == 16
    matrix = []
    for i in range (4):
        row = []
        for j in range (4):
            row.append(block[i*4+j])
        matrix.append(row)
    return matrix

## From matrix to 16 byte block
def matrix2block(matrix):
    block = []
    for i in range (4):
        for j in range (4):
            block.append(matrix[i][j])
    return block

## Byte sostitution
def byte_substitution(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j]=s_box[matrix[i][j]]
def inv_byte_substitution(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j]=inv_s_box[matrix[i][j]]

## Shift rows
def shift_rows(matrix):
    row1=[matrix[1][1],matrix[1][2],matrix[1][3],matrix[1][0]]
    row2=[matrix[2][2],matrix[2][3],matrix[2][0],matrix[2][1]]
    row3=[matrix[3][3],matrix[3][0],matrix[3][1],matrix[3][2]]
    matrix[1]=row1
    matrix[2]=row2
    matrix[3]=row3
def inv_shift_rows(matrix):
    row1=[matrix[1][3],matrix[1][0],matrix[1][1],matrix[1][2]]
    row2=[matrix[2][2],matrix[2][3],matrix[2][0],matrix[2][1]]
    row3=[matrix[3][1],matrix[3][2],matrix[3][3],matrix[3][0]]
    matrix[1]=row1
    matrix[2]=row2
    matrix[3]=row3

## Mix columns
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(row):
    # see Sec 4.1.2 in The Design of Rijndael
    t = row[0] ^ row[1] ^ row[2] ^ row[3]
    u = row[0]
    row[0]^=(t ^ xtime(row[0] ^ row[1]))
    row[1]^=(t ^ xtime(row[1] ^ row[2]))
    row[2]^=(t ^ xtime(row[2] ^ row[3]))
    row[3]^=(t ^ xtime(row[3] ^ u))
def mix_columns(matrix):
    for i in range(4):
        mix_single_column(matrix[i])
def inv_mix_columns(matrix):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(matrix[i][0] ^ matrix[i][2]))
        v = xtime(xtime(matrix[i][1] ^ matrix[i][3]))
        matrix[i][0] ^= u
        matrix[i][1] ^= v
        matrix[i][2] ^= u
        matrix[i][3] ^= v

    mix_columns(matrix)

def xor_word(word1,word2):
    return list(map(lambda x,y: x^y,word1,word2))
 
## Key expansion
def g(word,round):
    to_ret=[]
    to_ret.append(word[1])
    to_ret.append(word[2])
    to_ret.append(word[3])
    to_ret.append(word[0])
    for i in range(4):
        to_ret[i]=s_box[to_ret[i]]
    to_ret[0]^=rc[round]
    return to_ret
def key_schedule(k_matrix):
    expanded_key=[]
    prev_round=[]
    #10+1 rounds
    #Init
    for i in range(4):
        expanded_key.append(k_matrix[i])
        prev_round.append(k_matrix[i])
    #Round 0-10
    for i in range(10):
        word0 = xor_word(prev_round.pop(0),g(prev_round[2],i))
        word1 = xor_word(word0,prev_round.pop(0))
        word2 = xor_word(word1,prev_round.pop(0))
        word3 = xor_word(word2,prev_round.pop(0))

        expanded_key.append(word0)
        expanded_key.append(word1)
        expanded_key.append(word2)
        expanded_key.append(word3)
        
        prev_round.append(word0)
        prev_round.append(word1)
        prev_round.append(word2)
        prev_round.append(word3)

    return expanded_key

## Key additoion
def key_addition(t_matrix,k_matrix):
    for i in range(4):
        t_matrix[i]=xor_word(t_matrix[i],k_matrix[i])

## Aes for 16 byte block
def encrypt_block(block,subkeys):
    text_matrix = block2matrix(block)
    key_addition(text_matrix,[subkeys[0],subkeys[1],subkeys[2],subkeys[3]])
    for i in range(1,10):
        byte_substitution(text_matrix)
        shift_rows(text_matrix)
        mix_columns(text_matrix)
        key_addition(text_matrix,[subkeys[i*4+0],subkeys[i*4+1],subkeys[i*4+2],subkeys[i*4+3]]) 
    byte_substitution(text_matrix)
    shift_rows(text_matrix)
    key_addition(text_matrix,[subkeys[40],subkeys[41],subkeys[42],subkeys[43]])
    return matrix2block(text_matrix)
def decrypt_block(block,subkeys):
    sub_matrix = block2matrix(block)
    key_addition(sub_matrix,[subkeys[40],subkeys[41],subkeys[42],subkeys[43]])
    inv_shift_rows(sub_matrix)
    inv_byte_substitution(sub_matrix)
    for i in range(9,0,-1):
        key_addition(sub_matrix,[subkeys[i*4+0],subkeys[i*4+1],subkeys[i*4+2],subkeys[i*4+3]]) 
        inv_mix_columns(sub_matrix)
        inv_shift_rows(sub_matrix)
        inv_byte_substitution(sub_matrix)
    key_addition(sub_matrix,[subkeys[0],subkeys[1],subkeys[2],subkeys[3]])
    return matrix2block(sub_matrix)
### ECB
def aes128_ecb_encrypt(plaintext,key):
    if type(plaintext) is not list:
        plaintext = list(plaintext)
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(plaintext,True)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    encrypted_blocks = []
    for block in text_blocks:
        encrypted_blocks.append(encrypt_block(block,subkeys))
    encrypted_text=blocks2text(encrypted_blocks)
    return encrypted_text
def aes128_ecb_decrypt(encrypted_text,key):
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(encrypted_text)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    decrypted_blocks = []
    for block in text_blocks:
        decrypted_blocks.append(decrypt_block(block,subkeys))
    decrypted_text=blocks2text(decrypted_blocks,True)
    return bytes(decrypted_text)

### CBC
def aes128_cbc_encrypt(plaintext,key,iv):
    if type(plaintext) is not list:
        plaintext = list(plaintext)
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(plaintext,True)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    encrypted_blocks = []
    previous_block = list(iv)
    for block in text_blocks:
        encrypted_block=encrypt_block(xor_word(previous_block,block),subkeys)
        encrypted_blocks.append(encrypted_block)
        previous_block=encrypted_block
    encrypted_text=blocks2text(encrypted_blocks)
    return encrypted_text 
def aes128_cbc_decrypt(plaintext,key,iv):
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(plaintext)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    decrypted_blocks = []
    previous_block = list(iv)
    for block in text_blocks:
        decrypted_block=xor_word(previous_block,decrypt_block(block,subkeys))
        decrypted_blocks.append(decrypted_block)
        previous_block=block
    decrypted_text=blocks2text(decrypted_blocks,True)
    return bytes(decrypted_text)

### CFB
def aes128_cfb_encrypt(plaintext,key,iv):
    if type(plaintext) is not list:
        plaintext = list(plaintext)
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(plaintext,True)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    encrypted_blocks = []
    previous_block = list(iv)
    for block in text_blocks:
        encrypted_block=xor_word(encrypt_block(previous_block,subkeys),block)
        encrypted_blocks.append(encrypted_block)
        previous_block=encrypted_block
    encrypted_text=blocks2text(encrypted_blocks)
    return encrypted_text 
def aes128_cfb_decrypt(plaintext,key,iv):
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(plaintext)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    decrypted_blocks = []
    previous_block = list(iv)
    for block in text_blocks:
        decrypted_block=xor_word(block,encrypt_block(previous_block,subkeys))
        decrypted_blocks.append(decrypted_block)
        previous_block=block
    decrypted_text=blocks2text(decrypted_blocks,True)
    return bytes(decrypted_text)

### OFB
def aes128_ofb_encrypt(plaintext,key,iv,padding=True):
    if type(plaintext) is not list:
        plaintext = list(plaintext)
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(plaintext,padding)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    encrypted_blocks = []
    previous_block = list(iv)
    for block in text_blocks:
        output_block=encrypt_block(previous_block,subkeys)
        encrypted_block=xor_word(output_block,block)
        encrypted_blocks.append(encrypted_block)
        previous_block=output_block
    encrypted_text=blocks2text(encrypted_blocks,not padding)
    return encrypted_text 
def aes128_ofb_decrypt(plaintext,key,iv):
    if type(key) is not list:
        key = list(key)
    decrypted_text=aes128_ofb_encrypt(plaintext,key,iv,False)
    return bytes(decrypted_text)


### CTR with nonce
def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def aes128_ctr_encrypt(plaintext,key,nonce):
    if type(plaintext) is not list:
        plaintext = list(plaintext)
    if type(key) is not list:
        key = list(key)
    text_blocks= text2blocks(plaintext,True)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    encrypted_blocks = []
    for block in text_blocks:
        encrypted_block=xor_word(encrypt_block(nonce,subkeys),block)
        encrypted_blocks.append(encrypted_block)
        inc_bytes(nonce)
    encrypted_text=blocks2text(encrypted_blocks)
    return encrypted_text 
def aes128_ctr_decrypt(plaintext,key,nonce):
    text_blocks= text2blocks(plaintext)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    decrypted_blocks = []
    for block in text_blocks:
        decrypted_block=xor_word(block,encrypt_block(nonce,subkeys))
        decrypted_blocks.append(decrypted_block)
        inc_bytes(nonce)
    decrypted_text=blocks2text(decrypted_blocks,True)
    return bytes(decrypted_text )