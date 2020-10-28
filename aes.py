"""

    Python AES-128 Implementation

"""


#Precompted S-BOX...
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
#...and INV-S_BOX
inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)
#Precomputed RC for all key steps
rc = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)
#128 bit plaintext and key, form ascii code
plaintext=b'aiaiaia'*1000000
key=list(b'keyy'*4)
### PKCS#7 padding
def pad(text):
    check=len(text) % 16
    padding_len=16-check
    return text+[padding_len]*padding_len
def remove_padding(text):
    padding_len=text[-1]
    return text[0:-padding_len]
### From plaintext to 16 byte block for encrypt
def text2blocks(text,add_padding=False):
    blocks=[]
    if add_padding:
        text=pad(text)
    for i in range (0,len(text),16):
       blocks.append(text[i:i+16])
    return blocks

## From blocks to text
def blocks2text(blocks,padding=False):
    to_ret=list(sum(blocks,[]))
    if padding:
        to_ret=remove_padding(to_ret)
    return to_ret
    
## From 16 bit block to matrix
def block2matrix(block):
    assert len(block) == 16
    matrix = []
    for i in range (4):
        row = []
        for j in range (4):
            row.append(block[i*4+j])
        matrix.append(row)
    return matrix
def matrix2block(matrix):
    block = []
    for i in range (4):
        for j in range (4):
            block.append(matrix[i][j])
    return block

def byte_substitution(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j]=s_box[matrix[i][j]]
def inv_byte_substitution(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j]=inv_s_box[matrix[i][j]]

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

def xor_word(word1,word2):
    return list(map(lambda x,y: x^y,word1,word2))

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

def key_addition(t_matrix,k_matrix):
    for i in range(4):
        t_matrix[i]=xor_word(t_matrix[i],k_matrix[i])

def aes128_encrypt(plaintext,key):
    if type(plaintext) is str:
        plaintext=list(bytearray(plaintext,encoding='UTF-8'))
    if type(plaintext) is not list:
        plaintext = list(plaintext)
    text_blocks= text2blocks(plaintext,True)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    encrypted_blocks = []
    for block in text_blocks:
        text_matrix = block2matrix(block)
        key_addition(text_matrix,[subkeys[0],subkeys[1],subkeys[2],subkeys[3]])
        for i in range(1,11):
            byte_substitution(text_matrix)
            shift_rows(text_matrix)
            if i < 10:
                mix_columns(text_matrix)
                key_addition(text_matrix,[subkeys[i*4+0],subkeys[i*4+1],subkeys[i*4+2],subkeys[i*4+3]]) 
            else:
                key_addition(text_matrix,[subkeys[i*4+0],subkeys[i*4+1],subkeys[i*4+2],subkeys[i*4+3]])
                encrypted_blocks.append(matrix2block(text_matrix))
    encrypted_text=blocks2text(encrypted_blocks)
    return encrypted_text
def aes128_decrypt(encrypted_text,key):
    text_blocks= text2blocks(encrypted_text)
    key_matrix = block2matrix(text2blocks(key)[0])
    subkeys    = key_schedule(key_matrix)
    decrypted_blocks = []
    for block in text_blocks:
        sub_matrix = block2matrix(block)
        for i in range(10,-1,-1):
            key_addition(sub_matrix,[subkeys[i*4+0],subkeys[i*4+1],subkeys[i*4+2],subkeys[i*4+3]]) 
            if i > 0: 
                if i < 10:
                    inv_mix_columns(sub_matrix)
                    inv_shift_rows(sub_matrix)
                    inv_byte_substitution(sub_matrix)
                else:
                   inv_shift_rows(sub_matrix)
                   inv_byte_substitution(sub_matrix)
        decrypted_blocks.append(matrix2block(sub_matrix))
    decrypted_text=blocks2text(decrypted_blocks,True)
    return bytes(decrypted_text)
    



import time

start = time.time()
#print("plain: "+str(plaintext))
#print("key: "+ str(key))
enc=aes128_encrypt(plaintext,key)
#print("e_text: "+ str(enc))
dec=aes128_decrypt(enc,key)
print("d_text: "+ str(dec))

end = time.time()
print(end - start)
print(dec==plaintext)
from Crypto.Cipher import AES
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
start = time.time()
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plain = cipher.decrypt(ciphertext)
end = time.time()
print(end-start)
print(plaintext==plain)