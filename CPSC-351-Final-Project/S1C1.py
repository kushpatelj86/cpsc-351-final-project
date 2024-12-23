b64_index_table = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
                   'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
                   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 
                   'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
                   'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
                   'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
                   'w', 'x', 'y', 'z', '0', '1', '2', '3', 
                   '4', '5', '6', '7', '8', '9', '+', '/']

def hextoB64(hexchar):
    digit_string = ''
    for char in hexchar:
        dec = bin(int(char, 16))[2:]
        newdec = dec.zfill(4)
        digit_string += newdec
    
    paddeddigitstring6 = digit_string.zfill(6) #thing function provides padding 

    sixbitlist = [paddeddigitstring6[i:i+6] for i in range(0, len(paddeddigitstring6), 6)]
    
    newstr = ''
    for bits in sixbitlist:
        num = int(bits, 2)  
        newstr += b64_index_table[num] 
    
    
    
    print("Base64 Encoded String:", newstr)
    return newstr





if __name__=="__main__":
    test = hextoB64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')  
    print("is equal ", test == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

