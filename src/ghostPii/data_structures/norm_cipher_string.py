# basic modules
import numpy as np
import pandas as pd
import json
from sqlalchemy import *

#a tapas of additional scientific computing 
from scipy.spatial import distance

#capnion submodules

from ..encoding import *
from ..ciphertext import *
from ..num_theory_toolbox import *
from ..db_toolbox import *
from ..polynomial import *

import urllib.parse


#need to clarify how apiContexts should behave when these objects are added
#this is the main class for doing string computations on encrypted data
class NormCipherString:
    def __init__(self,apiContext,cipherList,indexData=False,keyRange=2000,permLevel='standard'):
        # api context is an important enduring property of the object
        self.apiContext = apiContext
        
        # if we are passed a string, we will encrypt it for the user
        if isinstance(cipherList,str):
            encoded_str = encode(cipherList)
            myLen = len(encoded_str)
            if permLevel == 'standard':
                myKeyLoc = apiContext.get('/state/?length='+str(myLen))[0]
            else:
                myKeyLoc = apiContext.get('/state/?length='+str(myLen)+'&permLevel='+urllib.parse.quote(permLevel)+'&keyRange='+str(keyRange))[0]
            #print(myKeyLoc)
            dataBoundary = [myKeyLoc['minId'],myKeyLoc['maxId']]
            myKeyGenerator = encryption_key(apiContext,dataBoundary,htmlDebug=False,seedString=False)
            #print(myKeyGenerator)
            keyData = []
    
            for atom in myKeyGenerator:
                keyData.append(atom['atom_key'])
            encrypted_str = []
            for i in range(len(encoded_str)):
                encrypted_str.append(encoded_str[i]+keyData[i])
            
            indexData = dataBoundary[0]
            self.cipherList = encrypted_str
        else:
            self.cipherList = cipherList  
        self.length = len(cipherList)

        
        #index data may be an integer, indicating an idAnchor and continuous indices
        #or it may be a an explicit list of indices
        if isinstance(indexData,int):
            self.indicesList = [indexData+i for i in range(len(cipherList))]
        else:
            self.indicesList = indexData
            
        self.pairsList = zip(self.indicesList,self.cipherList)
        
    def __len__(self):
        return len(self.cipherList)
        
    def __str__(self):
        return ",".join(['('+str(t[0])+','+str(t[1])+')' for t in self.pairsList])
    
    def __hash__(self):
        return sum([t.residue() for t in self.cipherList]) % 32767 #max value for a key integer
    
    def __getitem__(self, key):
        return NormCipherString(
            self.apiContext,
            self.cipherList[key],
            indexData = self.indicesList[key]
        )
    
    def __getslice__(self, i, j):
        return self.__getitem__(slice(i, j))
    
    def __iter__(self):
        for i in range(len(self.cipherList)):
            yield self[slice(i,i+1)]
    
    def __add__(self, other):
        return NormCipherString(
            self.apiContext,
            self.cipherList+other.cipherList,
            indexData = self.indicesList+other.indicesList
        )
    
    #this is key functionality and the most basic to require the API
    def __eq__(self, other): 
        if self.length != other.length:
            print("Ciphertext lengths are different.")
            return False
        else: 
            
            link = linking_key(self.apiContext,json.dumps(self.indicesList+other.indicesList))
            
            queryModulus = link[0]['prime']
            linkDict = id_dict(link)
            
            equal = False
            byCharEqual = []
            
            #we are using the presumption that the normcipherstrings are the same length
            for t in range(self.length):
                selfProd = polyn_comp_prod(linkDict[self.indicesList[t]],self.cipherList[t],queryModulus)
                otherProd = polyn_comp_prod(linkDict[other.indicesList[t]],other.cipherList[t],queryModulus)
                
                byCharEqual.append(selfProd == otherProd)
                
            equal = all(byCharEqual)
                
            return equal
        
    def __lt__(self,other):
        return [t.residue() for t in self.cipherList] < [t.residue() for t in other.cipherList]
    
    def pad(self,charsToAdd):
        encryptPadding = NormCipherString(self.apiContext,' '*charsToAdd)
        return NormCipherString(
            self.apiContext,
            self.cipherList + encryptPadding.cipherList,
            indexData = self.indicesList + encryptPadding.indicesList
        )
    
    #default to the standard encoding if no explicit map is given
    def ciphertext(self,encodeList=False):
        return encode_ciphertext(self.cipherList,encodeList)
    
    def decrypt(self):
        decryptKeyDict = {t['id']:t['atom_key'] for t in decryption_key(
            self.apiContext,
            json.dumps(self.indicesList)
        )}
        decryptKey = [decryptKeyDict[i] for i in self.indicesList]
        return ''.join([chr(t[0]-t[1]) for t in zip(self.cipherList,decryptKey)])      



#mostly a clone of the NCS class but with overloads that don't hit the API
#this is the secondary class for doing string computations on encrypted data
class AnalyticsCipherString:
    def __init__(self,apiContext,cipherList,helper,indexData,key):
        # api context is an important enduring property of the object
        self.apiContext = apiContext
        self.helper = helper
        self.num = key
        
        # if we are passed a string, we will encrypt it for the user
        if isinstance(cipherList,str):
            encoded_str = encode(cipherList)
            myLen = len(encoded_str)
            myKeyLoc = apiContext.get('https://ghostpii.com/state/?length='+str(myLen))[0]
            dataBoundary = [myKeyLoc['minId'],myKeyLoc['maxId']]
            encPerm = {'encrypt':dataBoundary}
            apiContext.post('https://ghostpii.com/keys/',{"assigned_user":apiContext.userId,"keyJSON":json.dumps(encPerm)} )
            myKeyGenerator = encryption_key(apiContext,dataBoundary,htmlDebug=False,seedString=False)
            keyData = []
    
            for atom in myKeyGenerator:
                keyData.append(atom['atom_key'])
            encrypted_str = []
            for i in range(len(encoded_str)):
                encrypted_str.append(encoded_str[i]+keyData[i])
            
            indexData = dataBoundary[0]
            self.cipherList = encrypted_str
        else:
            self.cipherList = cipherList 
        self.length = len(cipherList)

        
        #index data may be an integer, indicating an idAnchor and continuous indices
        #or it may be a an explicit list of indices
        if isinstance(indexData,int):
            self.indicesList = [indexData+i for i in range(len(cipherList))]
        else:
            self.indicesList = indexData
            
        self.pairsList = zip(self.indicesList,self.cipherList)
        
    def __len__(self):
        return len(self.cipherList)
        
    def __str__(self):
        return ",".join(['('+str(t[0])+','+str(t[1])+')' for t in self.pairsList])
    
    def __hash__(self):
        return sum([t.residue() for t in self.cipherList]) % 32767 #max value for a key integer
    
    def __getitem__(self, key):
        if isinstance(key,slice):
            return AnalyticsCipherString(self.apiContext,[self.cipherList[key]],self.helper,self.indicesList[key], self.num+key.start)
        else:
            return AnalyticsCipherString(self.apiContext,[self.cipherList[key]],self.helper,self.indicesList[key], self.num+key)
    
    def __iter__(self):
        for i in range(len(self.cipherList)):
            yield self[slice(i,i+1)]
    
    #this is key functionality and the most basic to require the API
    def __eq__(self, other): 
        equals = self.helper.checkEquality(self.indicesList,other.indicesList,self.num,other.num)
        return equals
        
    #default to the standard encoding if no explicit map is given
    def ciphertext(self,encodeList=False):
        return encode_ciphertext(self.atomList,encodeList)

#strictly a helper function that stores some needed info about the NormCipherList
#and gives the AnalyticsCipherStrings access to that info for distances and equality checking
class AnalyticsHelper:
    
    def __init__(self,apiContext,matrix,indexOffset):
        self.apiContext = apiContext
        self.matrix = matrix
        self.offset = indexOffset
    
    def checkEquality(self,index1,index2,num1,num2):
        
        answer = True
        
        for i in range(len(index1)):
            ind1 = num1 + i
            ind2 = num2 + i
            if(self.matrix[ind1][ind2] == 1):
                answer = answer and True
            else:
                return False
            
        return answer

