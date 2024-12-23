def fixedXor(str1,str2):
    
    if len(str1) != len(str2):
        raise ValueError("Input strings must have the same length.")
    
    newstr = ""
    
    
    newstr = ""
    for i in range(0, len(str1)):
        xor1 = int(str1[i],16)
        xor2 = int(str2[i],16)

        xor = xor1 ^ xor2
        strxr = hex(xor)[2:]
        newstr += strxr

    print(newstr)
    return newstr









if __name__=="__main__":
    test = fixedXor("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")
    print("is equal ", test == "746865206b696420646f6e277420706c6179")