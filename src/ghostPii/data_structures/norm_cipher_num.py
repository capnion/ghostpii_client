# basic modules
import numpy as np
import pandas as pd
import json
from sqlalchemy import *
import urllib.parse

#a tapas of additional scientific computing 
from scipy.spatial import distance

#capnion submodules

from ..encoding import *
from ..ciphertext import *
from ..num_theory_toolbox import *
from ..db_toolbox import *
from ..polynomial import *

class NormCipherNum:
    def __init__(self, apiContext,cipher,index=False,fromPlain=False,floatData=False,keyRange = 2000,permLevel='standard'):
        
        if isinstance(permLevel,dict):
            permLevel = json.dumps(permLevel)
        self.permLevel = permLevel

        if fromPlain == True:
            #in this scenario cipher is actually a plaintext integer
            #register data
            myKeyLoc = apiContext.get('/state/?length=1'+'&range='+str(keyRange)+'&permLevel='+urllib.parse.quote(permLevel))            
            #determine key boundaries
            dataBoundary = [myKeyLoc[0]['minId'],myKeyLoc[0]['maxId']]
            
           
            #pull enc key and encrypt
            myKeyGenerator = encryption_key(apiContext,dataBoundary,htmlDebug=False,seedString=False)
            keyData = []
            if type(cipher) is int:
                for atom in myKeyGenerator:
                    keyData.append(atom['atom_key'])
                self.floatData = False
            else:
                for atom in myKeyGenerator:
                    keyData.append(atom['atom_key']+atom['atom_key_inv']/32767)
                self.floatData = True
                
            #final addition step
            self.cipher = cipher + keyData[0]
            self.index = dataBoundary[0]
            
                                      
        else:
                                      
            self.cipher = cipher
            self.index = index
            self.floatData = floatData
        
        self.apiContext = apiContext

        
    def __len__(self):
        return 1
        
    def __str__(self):
        return True
    
    def __hash__(self):
        return sum([(t**2 % 10000) for t in cipherList]) % 10000
    
    def __add__(self, other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        polyString = 'x+y'
        variables = ['x','y']
        
        ans = full_polynomial_compute(self.apiContext,polyString,variables,myIndices,
                                      cipherPair,self.floatData,paillier=False,outPlain=False)
        
        return ans[0]
        
    
    def __sub__(self, other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        polyString = 'x-y'
        variables = ['x','y']
        
        ans = full_polynomial_compute(self.apiContext,polyString,variables,myIndices,
                                      cipherPair,self.floatData,paillier=False,outPlain=False)
        
        return ans[0]
    
    
    def __mul__(self, other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        polyString = 'x*y'
        variables = ['x','y']
        
        ans = full_polynomial_compute(self.apiContext,polyString,variables,myIndices,
                                      cipherPair,self.floatData,paillier=False,outPlain=False)
        
        return ans[0]
    
    def __pow__(self, other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        polyString = 'x ** y'
        variables = ['x','y']
        
        ans = full_polynomial_compute(self.apiContext,polyString,variables,myIndices,
                                      cipherPair,self.floatData,paillier=False,outPlain=False)
        
        return ans[0]

    #this functions well but is not actually homomorphic
    def __lt__(self,other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        
        plainResults = full_polynomial_compute(self.apiContext,'random-comparison',['x','y'],myIndices,cipherPair,
                                               isFloat=self.floatData,paillier=False,outPlain=True)
        return plainResults[0] < 0
       
    
    def __le__(self,other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        
        plainResults = full_polynomial_compute(self.apiContext,'random-comparison',['x','y'],myIndices,cipherPair,
                                               isFloat=self.floatData,paillier=False,outPlain=True)
        return round(plainResults[0],2) <= 0
    
    def __gt__(self,other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        
        plainResults = full_polynomial_compute(self.apiContext,'random-comparison',['x','y'],myIndices,cipherPair,
                                               isFloat=self.floatData,paillier=False,outPlain=True)
        return plainResults[0] > 0
    
    def __ge__(self,other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        
        plainResults = full_polynomial_compute(self.apiContext,'random-comparison',['x','y'],myIndices,cipherPair,
                                               isFloat=self.floatData,paillier=False,outPlain=True)
        return round(plainResults[0],2) >= 0
        
    def __eq__(self, other): 
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        
        plainResults = full_polynomial_compute(self.apiContext,'random-equality',['x','y'],myIndices,cipherPair,
                                               isFloat=self.floatData,paillier=False,outPlain=True)
        return round(plainResults[0],2) == 0
    
    def __ne__(self, other):
        myIndices = [(self.index,other.index,),]
        cipherPair = [[self.cipher,other.cipher]]
        
        plainResults = full_polynomial_compute(self.apiContext,'random-equality',['x','y'],myIndices,cipherPair,
                                               isFloat=self.floatData,paillier=False,outPlain=True)
        return round(plainResults[0],2) != 0
    
    def decrypt(self):
    
        if type(self.cipher) is int:
            decryptKeyDict = {t['id']:t['atom_key'] for t in decryption_key(self.apiContext,json.dumps([self.index]))}
            decryptKey = decryptKeyDict[self.index]
            return self.cipher - decryptKey
        else:
            decryptKeyDict = {t['id']:(t['atom_key'],t['atom_key_inv']) for t in decryption_key(
                self.apiContext,
                json.dumps([self.index])
            )}
            decryptKey = decryptKeyDict[self.index]
            return self.cipher - (decryptKey[0]+decryptKey[1]/32767)
       
    
    def ciphertext(self,encodeList = False):
        
        return encode_ciphertext([self.cipher],encodeList)

