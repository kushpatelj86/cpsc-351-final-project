#!/usr/bin/env python3


import math
from base64 import b64encode, b64decode




Sbox = [
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
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            ]

inv_s_box = [
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
]





round_constants = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
]




key_sizes_by_rounds = {16: 10, 24 : 12, 32: 14}


BLOCK_SIZE =16




def sub_bytes(s):
    for i in range(len(s)):
        for j in range(len(s)):
            s[i][j] = Sbox[s[i][j]]


def inv_sub_bytes(s):
    for i in range(len(s)):
        for j in range(len(s)):
            s[i][j] = inv_s_box[s[i][j]]





def shift_rows(s):


    for col in range(1, len(s)): 
        temp = [s[row][col] for row in range(len(s))]
        shift = col
        shifted = temp[shift:] + temp[:shift]
        for row in range(len(s)):
            s[row][col] = shifted[row]
        







def inv_shift_rows(s):


    for col in range(1, len(s)): 
        temp = [s[row][col] for row in range(len(s))]
        shift = col
        shifted = temp[-shift:] + temp[:-shift]
        for row in range(len(s)):
            s[row][col] = shifted[row]
        



    


def add_round_key(state, round_key):
 
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]






#performs GF(2^8)

def maskbits(a):
    if a & 0x80:  
        bits = ((a << 1) ^ 0x1B) & 0xFF 
        return bits 
    else:

        bits = (a << 1) & 0xFF
        return bits 

 

def mix_single_column(a):
    t = 0
    for num in a:
        t ^= num    
    u = a[0]



    for i in range(len(a) -1):
        a[i] ^= t ^ maskbits(a[i] ^ a[i+1])
    
    
    a[len(a) -1] ^= t ^ maskbits(a[len(a) -1] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):



    for row in s:

        a, b, c, d = row 
        u = maskbits(maskbits(a ^ c))
        v = maskbits(maskbits(b ^ d))

        for i in range(len(s)):
            if i % 2 == 0:
                row[i] ^= u
            else:
                row[i] ^= v


    mix_columns(s)




def bytesToMatrix(text):
    result = []
    for i in range(0, len(text), 4):
        result.append(list(text[i:i+4]))
    return result

def matrixToBytes(matrix):
    flattened_matrix = []
    for row in matrix:
        for element in row:
            flattened_matrix.append(element)
    return bytes(flattened_matrix)



def xor_bytes(a, b):
    result = bytearray(len(a))
    for i in range(len(a)):
        result[i] = a[i] ^ b[i]
    return bytes(result)





def pad(plaintext, block_size):
    padding_len = block_size - (len(plaintext) % block_size)
    if padding_len == block_size:
        return plaintext  
    padding = bytearray()
    for _ in range(padding_len):
        padding.append(padding_len)
    return plaintext + bytes(padding)

def unpad(plaintext):
    
    padding_len = plaintext[-1]
    return plaintext[0:len(plaintext) - padding_len]




    
def expand_key(master_key):
    
    key_columns = bytesToMatrix(master_key)
    iteration_size = len(master_key) // 4
    n_rounds = key_sizes_by_rounds[len(master_key)]

    keylen = len(master_key) 

    iteration = (n_rounds + 1) * 4 

    i = 1
    for n in range(len(key_columns), iteration):
        word = list(key_columns[-1])  

        if n % iteration_size == 0:  
            word.append(word.pop(0)) 
            word = [Sbox[b] for b in word]  
            word[0] ^= round_constants[i] 
            i += 1
        elif keylen == 32 and n % iteration_size == 4:  
            word = [Sbox[b] for b in word]

        word = xor_bytes(word, key_columns[-iteration_size])
        key_columns.append(word)

    coliter = len(key_columns) // 4
    result = []
    for i in range(coliter):
        result.append(key_columns[4*i : 4*(i+1)] )
    

    return result


  

def decrypt_block(key, ciphertext):
    
    matrix_key = expand_key(key)
    n_rounds = key_sizes_by_rounds[len(key)]

    cipher_state = bytesToMatrix(ciphertext)


    add_round_key(cipher_state, matrix_key[-1])
    inv_shift_rows(cipher_state)
    inv_sub_bytes(cipher_state)
    lastind = n_rounds - 1
    lastind = n_rounds - 1
    i = lastind

    while i > 0:
        add_round_key(cipher_state, matrix_key[i])
        inv_mix_columns(cipher_state)
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)
        i -= 1

    add_round_key(cipher_state, matrix_key[0])

    return matrixToBytes(cipher_state)





def encrypt_block(key, plaintext):

    matrix_key = expand_key(key)
    n_rounds = key_sizes_by_rounds[len(key)]

    plain_matrix = bytesToMatrix(plaintext)


    add_round_key(plain_matrix, matrix_key[0])
    
    i = 1

    while i < n_rounds:
        sub_bytes(plain_matrix)
        shift_rows(plain_matrix)
        mix_columns(plain_matrix)
        add_round_key(plain_matrix, matrix_key[i])
        i+=1

    sub_bytes(plain_matrix)
    shift_rows(plain_matrix)
    add_round_key(plain_matrix,matrix_key[-1])


    return matrixToBytes(plain_matrix)







def splitblocks(items, block_size):
    
    result = []
    for i in range(0, len(items), block_size):
        result.append(items[i:i + block_size])
    return result




def aes_ecb_decrypt(key, ciphertext):
    decrypted_blocks = []

    for b in splitblocks(ciphertext, BLOCK_SIZE):
        decrypted = decrypt_block(key, b)
        decrypted_blocks.append(decrypted)
    
    decrypted_data = b''
    
    for block in decrypted_blocks:
        
        decrypted_data += block
    
    unpaddedplaintext = unpad(decrypted_data)
    return unpaddedplaintext



def aes_ecb_encrypt(key, plaintext):
    padded = pad(plaintext,BLOCK_SIZE)
    result = b''
    for b in splitblocks(padded, BLOCK_SIZE):
        
        encrypted = encrypt_block(key, b)
        result += encrypted
    
    return result



def aes_cbc_decrypt(key, ciphertext, initilization_vector):

    encrypted_blocks = splitblocks(ciphertext, BLOCK_SIZE)
   

    decrypted_blocks = []
    prev = initilization_vector
    for block in encrypted_blocks:
        decrypted = decrypt_block(key,block)
        xored = xor_bytes(prev, decrypted)
        prev = block
        decrypted_blocks.append(xored)

    result = b''
    for block in decrypted_blocks:
        result += block
    
    unpaddedplaintext = unpad(result)
    return unpaddedplaintext






def aes_cbc_encrypt(key, ciphertext, initilization_vector):
    

    prev = initilization_vector
    encrypted_blocks = []
    paddedtext = pad(ciphertext,BLOCK_SIZE)

    decrypted_blocks = splitblocks(paddedtext, BLOCK_SIZE)

    for block in decrypted_blocks:
        xoredbytes = xor_bytes(prev, block)
        encrypted_block = encrypt_block(key,xoredbytes)
        encrypted_blocks.append(encrypted_block)
        prev = encrypted_block

    result = b''
    
    for block in encrypted_blocks:
        result += block
    
    return result








def cbc_mode():
    key = b'YELLOW SUBMARINE'
    initialization_vectoe = b'\x00' * BLOCK_SIZE

    key = b'YELLOW SUBMARINE'

    with open('S2C10.txt', 'rb') as file:  # 'rb' means reading in binary mode
        content = file.read()

    ciphertext = b64decode(content) #decodes the base 64 form to refgular form
    plaintext = aes_cbc_decrypt(key,ciphertext,initialization_vectoe)
    text_cleaned_str = plaintext.decode('utf-8')

    cleaned_text = text_cleaned_str.strip()  # Removes leading/trailing whitespace/newlines
    print(cleaned_text)



    iv = b'\x00' * BLOCK_SIZE
    key = b'YELLOW SUBMARINE'
    custom_input = b'Hello the world is gone there is no world, and there is a galaxy out for grabs in the unknown regions of the universe'
    print( aes_cbc_decrypt(key, aes_cbc_encrypt(key, custom_input, iv), iv) )







if __name__ == "__main__":
    cbc_mode()

