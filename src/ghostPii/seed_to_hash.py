import math
import hashlib 

"""
this module provides functionality for deterministically producing an encryption key locally
the primary function is string_to_key 
this module is intended for use with the HashKey endpoint...
...the more compact seed string is transmitted to the API where it is used to generate key data

SEED STRINGS SHOULD BE DESTROYED AT EARLIEST POSSIBLE OPPORTUNITY
"""

# calculates the Shannon entropy of a string
def entropy(string):
        
        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        # calculate the entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return entropy

# hash outputs are lists of characters, and this function matches trigrams to integers in the appropriate range    
def encoded_list_to_key(listOfHashes):
    keyList = []
    for i in range(len(listOfHashes)//3):
        keyAtom = 0
        for j in range(3):
            keyAtom+= (listOfHashes[3*i+j]*(102**j)) % 32767
        keyList.append(keyAtom)
    return keyList     

# this function enforces minimum standards on the complexity, in length and shannon entropy, of the seed string
def validate_seed(seedString):
    #input validation is very important here, need a string that is long and high entropy
    if len(seedString) > 8 and entropy(seedString) > 2:
        return True
    else:
        print("Please choose a longer and more complicated seed string.")
        return False

# this is the primary function intended for use outside this file
# this function takes a desired length and a complex seed string and produces an encryption key of appropriate length
# seed strings should not be retained in any form after submission to the API
def string_to_key(seedString,desiredLength):
    fullHashesRequired = desiredLength // 42
    lastHashLength = desiredLength - 42*fullHashesRequired
    
    superKeyList = []
    for i in range(fullHashesRequired):
        result = hashlib.sha512((seedString+str(i)).encode()) 
        superKeyList = superKeyList + encoded_list_to_key(list(result.hexdigest().encode()))
  
    #now compute keydata for the stub
    result = hashlib.sha512((seedString+str(fullHashesRequired+1)).encode()) 
    superKeyList = superKeyList + encoded_list_to_key(list(result.hexdigest().encode()))[0:lastHashLength]
    
    return superKeyList
