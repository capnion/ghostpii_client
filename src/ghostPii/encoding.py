import copy

def systematic_padding(listStrings,**kwargs):
    
    #examine different options for handling field length
    if 'maxLength' in kwargs:
        maxLength = kwargs.get('maxLength')
        keyLength = len(listStrings)*maxLength
    else:
        maxLength = max([len(t) for t in listStrings])
        keyLength = len(listStrings)*maxLength
    
    #create a new list if need be with all fields of the desired length
    return [t.ljust(maxLength) for t in listStrings]

def flatten_list(listOfList):
    return [item for sublist in listOfList for item in sublist]

# wrapper for the standard encoding
def encode(myString):
    return list(myString.encode())

# take a pandas frame, coerce to strings, pull information on length, pad to uniform length, and coerce to list of lists
def string_frame(dataFrame):
    listOfList = [ [str(s) for s in list(dataFrame[t])] for t in dataFrame ]
    colLengths = [ max([len(s) for s in colList]) for colList in listOfList ]
    
    listOfListPadded = [ [s.ljust(t[1]) for s in t[0]] for t in zip(listOfList,colLengths) ]
    
    return (listOfListPadded,colLengths,len(dataFrame.index)) 

#this function takes the output of 
def encode_frame(formattedFrame):
    return ([[encode(string) for string in column] for column in formattedFrame[0]],formattedFrame[1],formattedFrame[2])

def encode_list(dataList):
    colLength = max([len(s) for s in dataList])
    paddedList = [s.ljust(colLength) for s in dataList]
    return [encode(string) for string in paddedList]

"""
need to do some double checking on whether there can be issues with ordering change
"""

#uses the 'copy' module
#intended to take an encoded frame and have an atomic key integer added to every entry
def add_to_frame(encodedFrame,myKey):
    if sum(encodedFrame[1])*encodedFrame[2] != len(myKey):
        print(sum(encodedFrame[1])*encodedFrame[2],len(myKey))
        print(myKey)
        raise Exception("The supplied key is not the right size for the data.")
    
    #want a new encrypted frame and not to modify the old one
    toEncrypt = copy.deepcopy(encodedFrame)
    #one iteration over 
    atomicInd = 0 
    for colInd in range(len(encodedFrame[1])): 
        for rowInd in range(encodedFrame[2]): 
            for wordInd in range(encodedFrame[1][colInd]): 
                toEncrypt[0][colInd][rowInd][wordInd]+=myKey[atomicInd]['atom_key'] 
                atomicInd += 1
                
    return toEncrypt

#intended to take a cipher frame and decode before subtracting an atomic key integer from every entry
def sub_from_frame(cipherFrame,myKey,strip=False):
    if sum(cipherFrame.maxLength)*cipherFrame.rows != len(myKey):
        raise Exception("The supplied key is not the right size for the data.")    
    
    #want a new encrypted frame and not to modify the old one
    toDecrypt = copy.deepcopy(cipherFrame.ciphertext)
    #one iteration over 
    atomicInd = 0 
    for colInd in range(len(cipherFrame.maxLength)): 
        for rowInd in range(cipherFrame.rows): 
            for wordInd in range(cipherFrame.maxLength[colInd]): 
                toDecrypt[colInd][rowInd][wordInd]-=myKey[atomicInd]['atom_key'] 
                atomicInd += 1
            
            plainString = ''.join([chr(t) for t in toDecrypt[colInd][rowInd]])
                
            if strip == True:
                toDecrypt[colInd][rowInd] = plainString.strip()
            else:
                toDecrypt[colInd][rowInd] = plainString
            
    return toDecrypt

#uses the 'copy' module
#intended to take an encoded frame and have an atomic key integer added to every entry
def add_to_frame_gen(encodedFrame,myKeyGenerator):
    #!!!!!
    #need new error handling for length mismatch issues
   
    reverseMap = {}
    atomicInd = 0
    for colInd in range(len(encodedFrame[1])): 
        for rowInd in range(encodedFrame[2]): 
            for wordInd in range(encodedFrame[1][colInd]): 
                reverseMap[atomicInd] = {'colInd':colInd,'rowInd':rowInd,'wordInd':wordInd}
                atomicInd += 1
    
    #want a new encrypted frame and not to modify the old one - can we do better with memory here
    toEncrypt = copy.deepcopy(encodedFrame)
    #one iteration over 
    atomicInd = 0
    for atom in myKeyGenerator:
        #print(atomicInd,atom)
        colInd = reverseMap[atomicInd]['colInd']
        rowInd = reverseMap[atomicInd]['rowInd']
        wordInd = reverseMap[atomicInd]['wordInd']
        toEncrypt[0][colInd][rowInd][wordInd]+=atom['atom_key'] 
        atomicInd += 1
                
    return toEncrypt

