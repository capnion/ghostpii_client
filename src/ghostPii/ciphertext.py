"""
I am currently assuming the n in my ngrams is 3
"""

import pickle
import numpy as np

# create an ngrams file and dump a pickle in the current working directory
def pickle_coding(fileName):
    if type(fileName)!=str:
        raise Exception("Filename must be a string")

    # this logarithm computation was used original to figure out what the "n" in ngram should be
    #math.log(modulus,122)

    # these are the characters admitted in the ciphertext
    admChars = [chr(t) for t in range(33,123) if t not in [36,47,92]]
    # this forms the 3 fold combinations
    moreCharsEncode=[a+b+c for a in admChars for b in admChars for c in admChars]
    # open the file for writing
    fileObject = open(fileName,'wb') 
    # dump the list of ngrams as a file
    pickle.dump(moreCharsEncode,fileObject)   
    # close the file object
    fileObject.close()    

# this function takes a large integer index and returns a trigram representing it    
def proc_standard_encode(index):
    admChars = [chr(t) for t in range(33,123) if t not in [36,47,92]]
    interim = index
    trigram = ''
    for i in range(3):
        residue = interim % 87
        interim = (interim - residue) // 87
        trigram = trigram + admChars[residue]
    return trigram

def encode_float(index,precision=12):
    fullStr = ''
    curNum = int(index)
    prevNum = index
    for i in range(0,precision+1,4):
        fullStr += proc_standard_encode(curNum)
        prevNum -= curNum
        prevNum *= 10000
        curNum = int(prevNum)
        
    
    return fullStr

# maps a python encoding index to its entry in the list of admissible characters
def adm_char_ind(index):
    if index < 36:
        return index - 33
    elif index < 47:
        return index - 34
    elif index < 92:
        return index - 35
    else:
        return index - 36

# this function takes a trigram and returns the index of the large integer it represents    
def proc_standard_decode(trigram):
    letterIndices = [adm_char_ind(t) for t in list(trigram.encode())]
    fullIndex = 0
    for i in range(3):
        fullIndex+=letterIndices[i]*(87**i)
    return fullIndex

# load the coding map of the givern filename pickled in the current working directory
# and return two functions wrapping an encoding list and a decoding dict, respectively
def load_coding(fileName):
    if type(fileName)!=str:
        raise Exception("Filename must be a string")

    try:
        ngramsFile = open(fileName,'rb')
        ngrams = pickle.load(ngramsFile)
        ngramsFile.close()  
    except:
        pickle_coding(fileName)
        ngramsFile = open(fileName,'rb')
        ngrams = pickle.load(ngramsFile)
        ngramsFile.close()  

    def encode_func(charInt):
        return ngrams[charInt]

    decodeDict = dict(zip(ngrams,range(len(ngrams))))
    def decode_func(trigram):
        return decodeDict[trigram]

    return {'encodeList':encode_func,'decodeDict':decode_func}

#second argument actually presumed to be a function wrapping a list
def encode_ciphertext(ciphertextIntegers,codingData,precision=12):
    if codingData == False:
        encodeList = proc_standard_encode
    else:
        encodeList = codingData['encodeList']
    if isinstance(ciphertextIntegers[0],int):
        stringFragments = []
        for charInt in ciphertextIntegers:
            stringFragments.append(encodeList(charInt))
        return ''.join(stringFragments) + 'i'
    else:
        stringFragments = []
        for charFloat in ciphertextIntegers:
            stringFragments.append(encode_float(charFloat,precision))
        return ''.join(stringFragments)+ 'f'

#second argument actually presumed to be a function wrapping a dictionary
def decode_ciphertext(myString,decodeFunc=False):
    if decodeFunc == False:
        decodeFunc = proc_standard_decode
        
    ciphertextNums = []  
    if myString[-1] == 'i':
        myString = myString[0:len(myString)-1]
        
        for i in range(0, len(myString), 3):
            ciphertextNums.append(decodeFunc(myString[i:(i+3)]))
    else:
        ciphertextFloat = 0
        myString = myString[0:len(myString)-1]
        for i in range(0, len(myString), 3):
            ciphertextFloat += decodeFunc(myString[i:i+3])/10000**(i/3)
            
        ciphertextNums.append(ciphertextFloat)
    return ciphertextNums

#this function intended for a pandas frame of encrypted data encoded as ciphertext
def decode_frame(startingEncrypted,codingData=False):
    if codingData == False:
        decodeDict = proc_standard_decode
    else:
        decodeDict = codingData['decodeDict']


    listOfList = [ [decode_ciphertext(str(s),decodeDict) for s in list(startingEncrypted[t])] for t in startingEncrypted.columns]

    return listOfList