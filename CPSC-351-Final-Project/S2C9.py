def pad(data, numbytes):
    newData = data
    if len(data) >= numbytes:
        return newData
    
    newData = data
    diff = abs(len(data) - numbytes)
    if diff >= 0:
        for i in range(diff):
            newData += bytes([diff])
        return newData
    else:
        return newData



def is_padded(data):
    if data is None or len(data) == 0:
        return False  
    
    lastbyte = data[-1]

    if lastbyte == 0 or lastbyte > len(data):
        return False 
    
    paddedBytes = data[-lastbyte:]
    
    for i in paddedBytes:
        if i != lastbyte:
            return False
    
    return True


    

def unpad(data):
    
    isPadded = is_padded(data)

    if isPadded is True:
        
        lastByte = data[-1]

        ind = len(data) - lastByte

        newStr = data[0:ind]

        return newStr

    else:
        return data


def test_padding():
    message = b"YELLOW SUBMARINE"
    print(message)

    b = pad(message, 16)
    print("padded message: ",b)

    unpadb = unpad(b)
    print("unpadded message: ",unpadb)


if __name__ == "__main__":
    test_padding()  

