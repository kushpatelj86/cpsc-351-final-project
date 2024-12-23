from base64 import *
CHARACTER_FREQ = {
    b'a': 0.0651738, b'b': 0.0124248, b'c': 0.0217339, b'd': 0.0349835, b'e': 0.1041442, b'f': 0.0197881, b'g': 0.0158610,
    b'h': 0.0492888, b'i': 0.0558094, b'j': 0.0009033, b'k': 0.0050529, b'l': 0.0331490, b'm': 0.0202124, b'n': 0.0564513,
    b'o': 0.0596302, b'p': 0.0137645, b'q': 0.0008606, b'r': 0.0497563, b's': 0.0515760, b't': 0.0729357, b'u': 0.0225134,
    b'v': 0.0082903, b'w': 0.0171272, b'x': 0.0013692, b'y': 0.0145984, b'z': 0.0007836, b' ': 0.1918182
}

def get_score(input_bytes):
    
    score = 0

    for byte in input_bytes:
        lower_byte = bytes([byte])
        score += CHARACTER_FREQ.get(lower_byte.lower(), 0)

    return score

def single_xor(input_bytes, key_value):
    output = bytearray()  
    
    for char in input_bytes:
        output.append(char ^ key_value)  
    
    return bytes(output)


    

def find_best_candidate(text):
   

    best_candidate = None  
    ascii_chars = [(i) for i in range(256)]

    for i in ascii_chars:
        plaintext = single_xor(text, i)
        score = get_score(plaintext)
        result = {
            "key": i,
            "score": score,
            "plaintext": plaintext
        }
        if best_candidate is None or score > best_candidate["score"]:
            best_candidate = result

    return best_candidate

def print_result(result):
    try:
        print("text: ", result["plaintext"].decode().rstrip())
    except UnicodeDecodeError:
        print("text: <non-decodable>")
    
    
    print("score: ", result["score"])
    print("key: ", result["key"])

def repeat_key_xor(plaintext: bytes, key: bytes) -> bytes:
    key_len = len(key)
    ciphertext = bytearray(len(plaintext))

    for i in range(len(plaintext)):
        ciphertext[i] = plaintext[i] ^ key[i % key_len]
    
    return bytes(ciphertext)


def to_hex(bytes_data: bytes) -> str:
    return bytes_data.hex()

def hamming_distance(str1,str2):
    if len(str1) != len(str2):
        raise ValueError("Input strings must have the same length.")
    num = 0

    for b1, b2 in zip(str1, str2):
        differing_bits = b1 ^ b2
        for i in bin(differing_bits):
            if i == '1':
                 num+=1
                 

    return num




         









def break_repeating_keys_xor(binary_data):
    distances = {}
    for key_size in range(2,41):
        chunks = []
        for i in range(0, len(binary_data), key_size):
            chunks.append(binary_data[i:i + key_size])
            if len(chunks) == 4:
                break


        distance = 0
        iter = 0
        for i in range(len(chunks)):
            for j in range(i + 1, len(chunks)):  
                iter += 1
                distance += hamming_distance(chunks[i], chunks[j])

        


        average_distance = distance / iter

        normalized_distance = average_distance / key_size

        distances[key_size] = normalized_distance

    smallest_3_distances = sorted(distances.items(), key=lambda item: item[1])[:3]
    plaintext_candidates = {}

    for key_tuple in smallest_3_distances:
        key_size = key_tuple[0]  
        ky = b''

        for block in range(key_size):
            blk = b''
            n = len(binary_data)
            for i in range(block, n, key_size):  
                blk += bytes([binary_data[i]])

            solved_block = find_best_candidate(blk)['key']
            ky += bytes([solved_block])

        plaintext = repeat_key_xor(binary_data, ky)

        plaintext_candidates[ky] = {
            "plaintext": plaintext,
            "score": get_score(plaintext),
        }





    best_key = max(plaintext_candidates, key=lambda k: plaintext_candidates[k]["score"])
    best_plaintext = plaintext_candidates[best_key]["plaintext"]

    return best_plaintext, best_key





def decrypt():


    with open("S1C6.txt") as input_file:
        data = b64decode(input_file.read())

    result = break_repeating_keys_xor(data)
    print("Key=", result[1].decode())
    print(result[0].decode().rstrip())





if __name__ == "__main__":
    decrypt()


                