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

from .norm_cipher_num import NormCipherNum
from .paillier_num import PaillierFloat

class NormCipherQuant:
    def __init__(self, apiContext,cipherList,indexData=False,symbolic=False,
                 fromPlain=False,floatData=False,keyRange=2000,permLevel='standard'):
        
        if fromPlain == True:
            #in this scenario cipherIntegerList is actually a list of plaintext integers
            #register data
            if isinstance(permLevel,dict):
                permLevel = json.dumps(permLevel)
            myKeyLoc = apiContext.get('/state/?length='+str(len(cipherList))+'&range='
                                      +str(keyRange)+'&permLevel='+urllib.parse.quote(permLevel))[0]
            
            #determine key boundaries
            dataBoundary = [myKeyLoc['minId'],myKeyLoc['maxId']]
            
           
            #pull enc key and encrypt
            myKeyGenerator = encryption_key(apiContext,dataBoundary,htmlDebug=False,seedString=False)
            keyData = []
            
            #use integer pads or float pads depending on data type
            if all(isinstance(x, int) for x in cipherList) and not floatData:
                for atom in myKeyGenerator:
                    keyData.append(atom['atom_key'])
                self.floatData = False
            else:
                for atom in myKeyGenerator:
                    keyData.append(atom['atom_key']+atom['atom_key_inv']/32767)
                #print(keyData)
                self.floatData = True
                
                
                
            #final addition step
            self.cipherList = [t[0]+t[1] for t in zip(cipherList,keyData)]
            self.indicesList = list(range(dataBoundary[0],dataBoundary[1]))
            
            #initialized with each symbolic entry referring directly to a 
            self.symbolic = ['x%d'%(i,) for i in self.indicesList]
            
        else:
            self.cipherList = cipherList
            self.floatData = floatData
            
            #generate ids if given only an idAnchor
            if isinstance(indexData,int):
                self.indicesList = list(range(indexData,indexData+len(cipherList)))
            #otherwise just use the given list of ids
            else:
                self.indicesList = indexData       
        
        self.length = len(cipherList)
        self.nums = [i for i in range(self.length)]
        self.apiContext = apiContext
        self.permLevel = permLevel
        
        self.symbolic = symbolic

        
    def __len__(self):
        return self.length
        
    def __str__(self):
        return True
    
    def __hash__(self):
        return sum([(t**2 % 10000) for t in cipherList]) % 10000
    
    
    def __getslice__(self, start, stop):
        return NormCipherQuant(
            self.apiContext,
            self.cipherList[slice(start,stop)],
            self.indicesList[slice(start,stop)],
            floatData = self.floatData
        )

    #approximating a list of strings, so getting an item should give the normcipherstring
    def __getitem__(self, key):
        if isinstance(key, slice):
            return NormCipherQuant(
                self.apiContext,
                self.cipherList[key],
                self.indicesList[key],
                floatData = self.floatData
            )
        else:
            if type(self.nums[key]) != int:
                return self.nums[key]
            newNum = NormCipherNum(
                self.apiContext,
                self.cipherList[key],
                index = self.indicesList[key],
                floatData = self.floatData
            )
            self.nums[key] = newNum
            return newNum
    
    def __iter__(self):
        for i in range(len(self.cipherList)):
            yield self[slice(i,i+1)]

    def vert_slice(self,indexList):
        return NormCipherQuant(self.apiContext,
                               [self.cipherList[i] for i in indexList],
                               indexData=[self.indicesList[i] for i in indexList],
                               floatData = self.floatData
                              )
    
    def decrypt(self):
        if all(isinstance(x, int) for x in self.cipherList):
            
            decryptKeyDict = {t['id']:t['atom_key'] for t in decryption_key(
                self.apiContext,
                json.dumps(self.indicesList)
            )}
            decryptKey = [decryptKeyDict[i] for i in self.indicesList]
            #print(decryptKey)
            return [t[0]-t[1] for t in zip(self.cipherList,decryptKey)] 
        else:
            
            decryptKeyDict = {t['id']:(t['atom_key'],t['atom_key_inv']) for t in decryption_key(
                self.apiContext,
                json.dumps(self.indicesList)
            )}
            decryptKey = [decryptKeyDict[i] for i in self.indicesList]
            #print(decryptKey)
            return [t[0]-(t[1][0]+t[1][1]/32767) for t in zip(self.cipherList,decryptKey)] 
    
    def vert_merge(self, other):
        self.length = len(self.cipherList)+len(other.cipherList)
        return NormCipherQuant(
            self.apiContext,
            self.cipherList+other.cipherList,
            indexData = self.indicesList+other.indicesList,
            floatData = self.floatData
        )
    
    def mean(self):
        sumDecryptKey = ngram_checksum_key(
            self.apiContext,
            self.length,
            self.length,
            json.dumps(self.indicesList),
            isFloat=self.floatData
        )
        cipherSum = sum(self.cipherList)
        return (cipherSum - sumDecryptKey[0]['computed_range_sum'])/self.length

    def stdev(self):
        if self.length == 1:
            print("Must have length > 1 for standard deviation calculation")
            return "Length error"
        
        # get things we need for standard deviation calc
        mean = self.mean()
        polyString = "(x - {} )**2".format(mean)
        variables = ["x"]
        myIndices = [(i,) for i in self.indicesList]
        myCiphers = [(i,) for i in self.cipherList]
        
        # set up and solve the polynomial
        ans = full_polynomial_compute(self.apiContext,polyString,variables, myIndices, myCiphers, self.floatData,paillier=False,isSum=True,outPlain=True)
        
        std_dev = (ans/self.length) ** .5
        return std_dev
            
    def median(self):
        #need to change this to unknown polynomial
        variables = ['x']
        myIndices = [(i,) for i in self.indicesList]
        myCiphers = [(i,) for i in self.cipherList]
        # set up and solve the polynomial
       
        ans = full_polynomial_compute(self.apiContext,'random-median',variables, myIndices, myCiphers, self.floatData,paillier=False,isSum=False,outPlain=True)
        #print(ans)
        #sort the values
        index_val_tuples = []
        for i in range(self.length):
            index_val_tuples.append((i,ans[i]))
        
        sorted_list = sorted(index_val_tuples, key = lambda tup: tup[1])
        
        if len(sorted_list) % 2 == 0:
            #take the average of two in middle
            med_index1 = sorted_list[int(len(sorted_list)/2)][0]
            med_index2 = sorted_list[int(len(sorted_list)/2)-1][0]
            medNum = NormCipherNum(self.apiContext,self.cipherList[med_index1],index = self.indicesList[med_index1],floatData = self.floatData)
            medNum = medNum + NormCipherNum(self.apiContext,self.cipherList[med_index2],index = self.indicesList[med_index2],floatData = self.floatData)
            return medNum.decrypt()/2
            
        else:
            #return median
            med_index = med_index1 = sorted_list[len(sorted_list)//2][0]
            return NormCipherNum(self.apiContext,self.cipherList[med_index],index = self.indicesList[med_index],floatData = self.floatData)
        
        
    def cosine_similarity(self,other):
        if self.length != other.length:
            print("Cannot perform this operation on vectors of different lengths")
            return "Length Error"
        
        return self.dot_product(other) / (self.magnitude()*other.magnitude())
        
        
    def dot_product(self,other):
        if self.length != other.length:
            print("Cannot perform this operation on vectors of different lengths")
            return "Length Error"
        
        polyString = "x * y"
        variables = ['x', 'y']
        myIndices = [(self.indicesList[i],other.indicesList[i],) for i in range(self.length)]
        myCiphers = [(self.cipherList[i],other.cipherList[i],) for i in range(self.length)]
        # set up and solve the polynomial
        ans = full_polynomial_compute(self.apiContext,polyString,variables, myIndices, myCiphers, self.floatData,isSum=True,paillier=False,outPlain=True)
       
        return ans
        
    def coord_expon(self,n):
        polyString = "x ** %d" % (n,)
        variables = ['x']
        myIndices = [(i,) for i in self.indicesList]
        myCiphers = [(i,) for i in self.cipherList]
        # set up and solve the polynomial
        ans = full_polynomial_compute(self.apiContext,polyString,variables, myIndices, myCiphers, self.floatData,isSum=True,paillier=True,outPlain=True)
        return ans 
         
    def magnitude(self):
        polyString = "x ** 2"
        variables = ['x']
        myIndices = [(i,) for i in self.indicesList]
        myCiphers = [(i,) for i in self.cipherList]
        # set up and solve the polynomial
        ans = full_polynomial_compute(self.apiContext,polyString,variables, myIndices, myCiphers, self.floatData,isSum=True,paillier=True,outPlain=True)
        return ans ** .5
    
    def ciphertext(self,encodeList = False):
        cipherArray = []
        for i in range(len(self)):
            cipherArray.append(encode_ciphertext([self.cipherList[i]],encodeList))
        return cipherArray
    
    def list_of_ciphertext(self,encodeList = False):
        cipherArray = []
        for i in range(len(self)):
            cipherArray.append(encode_ciphertext([self.cipherList[i]],encodeList))
        return cipherArray
    
    def summation(self):
        sumDecryptKey = ngram_checksum_key(
            self.apiContext,
            self.length,
            self.length,
            json.dumps(self.indicesList),
            isFloat=self.floatData
        )
        cipherSum = sum(self.cipherList)
        #print(sumDecryptKey[0])
        return cipherSum - sumDecryptKey[0]['computed_range_sum']
    
    def __gt__(self,other):
        if isinstance(other,NormCipherNum):
            myIndices = [(self.indicesList[i],other.index,) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipher] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-comparison',['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)
            
            
            return [int(num > 0) for num in plainResults]
        elif isinstance(other, (int, float, complex,np.int64,np.float64)):
            other = NormCipherNum(self.apiContext,other,fromPlain=True,keyRange=20)
            myIndices = [(self.indicesList[i],other.index,) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipher] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-comparison',['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)
            
            
            return [int(num > 0) for num in plainResults]
        else:
            return False
        
    def __lt__(self,other):
        if isinstance(other,NormCipherNum):
            myIndices = [(self.indicesList[i],other.index,) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipher] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-comparison',['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)
            
            print(plainResults)
            return [int(num < 0) for num in plainResults]
        elif isinstance(other, (int, float, complex,np.int64,np.float64)):
            other = NormCipherNum(self.apiContext,other,fromPlain=True,keyRange=20)
            myIndices = [(self.indicesList[i],other.index,) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipher] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-comparison',
                                              ['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)
            
            print(plainResults)
            return [int(num < 0) for num in plainResults]
        else:
            return False
        
        
    def __eq__(self,other):
        
        if isinstance(other,NormCipherNum):
            myIndices = [(self.indicesList[i],other.index,) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipher] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-equality',['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)
            
            
            numList = [int(round(num) == 0) for num in plainResults]
            return sum(numList) == len(numList)
        elif isinstance(other,NormCipherQuant):
            if len(other) != self.length:
                return False
            myIndices = [(self.indicesList[i],other.indicesList[i],) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipherList[i]] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-equality',['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)
            
            
            numList = [int(round(num) == 0) for num in plainResults]
            return sum(numList) == len(numList)
        
        elif isinstance(other,list):
            if len(other) != self.length:
                return False
            other = NormCipherQuant(self.apiContext,other,fromPlain=True,keyRange=20,floatData=self.floatData)
            myIndices = [(self.indicesList[i],other.indicesList[i],) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipherList[i]] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-equality',['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)            
            
            numList = [int(round(num) == 0) for num in plainResults]
            return sum(numList) == len(numList)
            
        elif isinstance(other, (int, float, complex,np.int64,np.float64)):
            other = NormCipherNum(self.apiContext,other,fromPlain=True,keyRange=20)
            myIndices = [(self.indicesList[i],other.index,) for i in range(len(self.indicesList))]
            cipherPair = [[self.cipherList[i],other.cipher] for i in range(len(self.cipherList))]

            plainResults = full_polynomial_compute(self.apiContext,'random-equality',['x','y'],myIndices,cipherPair,isFloat=self.floatData,paillier=False,outPlain=True)
            
            
            numList = [int(round(num) == 0) for num in plainResults]
            return sum(numList) == len(numList)
        else:
            return False
    
