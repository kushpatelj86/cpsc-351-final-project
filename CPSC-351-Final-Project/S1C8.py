BLOCK_SIZE = 16




def count_repetitions(ciphertext):
    chunks = []
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        chunks.append(ciphertext[i:i + BLOCK_SIZE])
    
    reg =  len(chunks)
    sets = len(set(chunks))
    number_of_duplicates = reg - sets
    return number_of_duplicates


def detect_ecb_ciphertext(ciphertexts):
    best_candidate = None
    for i in range(len(ciphertexts)):
        reps = count_repetitions(ciphertexts[i])  
        
        if best_candidate is None or reps > best_candidate[1]:
            best_candidate = (i, reps)

    return best_candidate




def detect():

    ciphertexts = []
    with open("S1C8.txt", "r") as file:
        for line in file:
            ciphertexts.append(bytes.fromhex(line.strip()))


    best = detect_ecb_ciphertext(ciphertexts)

    print("The ciphertext encrypted in ECB mode is at position", best[0],
            "which contains", best[1], "repeated blocks.")
    print("Detected ECB ciphertext (hex):", ciphertexts[best[0]].hex())
    print(best[0] == 132)



if __name__ == "__main__":
    detect()
    


