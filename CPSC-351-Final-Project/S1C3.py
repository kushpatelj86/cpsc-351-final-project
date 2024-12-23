#used the github you sent for the character frequencies
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

def decrypt():
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    most_likely_plaintext = find_best_candidate(ciphertext)
    print_result(most_likely_plaintext)





if __name__ == "__main__":
    decrypt()

