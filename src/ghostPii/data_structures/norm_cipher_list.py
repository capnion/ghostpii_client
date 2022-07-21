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

from .norm_cipher_string import *

class NormCipherList:

    def __init__(self,apiContext,cipherListOfList,indexData=False,fromPlain=False,seedString=False,keyRange=2000,permLevel='standard'):
        
        if isinstance(permLevel,dict):
            permLevel = json.dumps(permLevel)
        self.permLevel = permLevel

        if fromPlain:
            importData = import_and_encrypt_list(cipherListOfList,apiContext,seedString,keyRange,permLevel=permLevel)
            self.cipherListOfList = importData[0]
            self.indicesListOfList = importData[1]
            
            
        else:
            #get list of group elements
            #the rawest version of the underlying data is a list of list of integers
            self.cipherListOfList = cipherListOfList
             #assumes entries the same length
            

            #index data may be an integer, indicating an idAnchor and continuous indices
            #or it may be a an explicit list of indices
            if isinstance(indexData,int):
                self.indicesListOfList = [] 
                i=indexData
                for cipherList in self.cipherListOfList:
                    self.indicesListOfList.append(list(range(i,i+len(cipherList))))
                    i+=len(cipherList)
            else:
                self.indicesListOfList = indexData
                
        self.colMaxChars = len(self.cipherListOfList[0])        
        self.apiContext = apiContext
        self.words = [i for i in range(len(self.cipherListOfList))]
        self.length = len(self.cipherListOfList)
        self.helper = 0
        
    def __len__(self):
        return len(self.cipherListOfList)#//self.maxLength

    def __getslice__(self, start, stop):
        return NormCipherList(
            self.apiContext,
            self.cipherListOfList[slice(start,stop)],
            indexData = self.indicesListOfList[slice(start,stop)]
        )

    #approximating a list of strings, so getting an item should give the normcipherstring
    def __getitem__(self, key):
        
        if isinstance(key, slice):
            return NormCipherList(
                self.apiContext,
                self.cipherListOfList[key],
                indexData = self.indicesListOfList[key]
            )
        else:
            if isinstance(self.words[key], int):
                ncs = NormCipherString(
                    self.apiContext,
                    self.cipherListOfList[key],
                    indexData = self.indicesListOfList[key]
                    )
                self.words[key] = ncs
                return ncs
            else:
                return self.words[key]
        
    def __iter__(self):
        for i in range(len(self.cipherListOfList)):
            yield self[slice(i,i+1)]
            
    def pad(self,charsToAdd):
        encryptPadding = NormCipherFrame(self.apiContext,pd.DataFrame([[' '*charsToAdd]*len(self.cipherListOfList)]).transpose())[0]
        return NormCipherList(
            self.apiContext,
            [
                cipherListTuple[0] + cipherListTuple[1] 
                for cipherListTuple in zip(self.cipherListOfList,encryptPadding.cipherListOfList)
            ],
            indexData = [
                indicesListTuple[0] + indicesListTuple[1] 
                for indicesListTuple in zip(self.indicesListOfList,encryptPadding.indicesListOfList)
            ]
        )
        
    def vert_merge(self, other):
        if type(other) == NormCipherList:
            return NormCipherList(
                self.apiContext,
                self.cipherListOfList+other.cipherListOfList,
                indexData = self.indicesListOfList+other.indicesListOfList
            )
        else:
            return NormCipherList(
                self.apiContext,
                self.cipherListOfList+[other.cipherList],
                indexData = self.indicesListOfList+[other.indicesList]
            )

    #the linking key endpoint needs to be updated to take into account the possibility of... 
    #...a more complicated list of indices
    def char_equal_mx(self):
        #using polynomial endpoint
        myCiphers = [[cipher] for word in self.cipherListOfList for cipher in word]
        myIndices = [[index] for word in self.indicesListOfList for index in word]
        
        
        plainResults = full_polynomial_compute(self.apiContext,'random-sort',['x'],myIndices,
                                               myCiphers,False,paillier=False,outPlain=True)
        #print(plainResults)
        charEqMx = []
        
        charsPerCol = len(self.cipherListOfList * self.colMaxChars)
        for i in range(len(plainResults)):
            for j in range(len(plainResults)):
                if round(plainResults[i]) == round(plainResults[j]):
                    charEqMx.append(1)
                else:
                    charEqMx.append(0)
                    
        outputArray = np.array(charEqMx)
        outputArray.shape = (charsPerCol,charsPerCol)
        #print(outputArray)
        return outputArray
    
    def ngram_hashes(self,n):
        ngramDecryptKey = [t['computed_range_sum'] for t in ngram_checksum_key(
            self.apiContext,
            n,
            self.colMaxChars,
            json.dumps(flatten_list(self.indicesListOfList))
        )]
        #print(ngramDecryptKey)
        i = 0
        ngramHashes = []
        for cellList in self.cipherListOfList:
            cellHashes = []
            for wordIndex in range(self.colMaxChars-n+1):
                cellHashes.append(sum(cellList[slice(wordIndex,wordIndex+n)])-ngramDecryptKey[i])
                i+=1
            ngramHashes.append(cellHashes)
        return ngramHashes
    
    def ngram_distance_matrix(self,n):
        hashes = self.ngram_hashes(n)
        outputArray = np.zeros((len(hashes),len(hashes)))
        for i in range(len(hashes)):
            for j in range(len(hashes)):
                outputArray[i,j] = distance.cosine(hashes[i],hashes[j])
        return outputArray
    
    def list_of_ciphertext(self,encodeList=False):
        return [encode_ciphertext(self[t].cipherList,encodeList) for t in range(len(self))]
    
    #this function homomorphically computes a simple hash function returning the sum of the encoded values
    #this presumes all entries in the list are the same length
    def checksum(self):
        checksumDecryptKey = ngram_checksum_key( 
            self.apiContext,
            self.colMaxChars,
            self.colMaxChars,
            json.dumps(flatten_list(self.indicesListOfList))
        )
        #print(self.colMaxChars)
        #print(checksumDecryptKey)
        checksumList = [
            t[0]-t[1]['computed_range_sum'] 
            for t in zip([sum(u) for u in self.cipherListOfList],checksumDecryptKey)
        ]
        return checksumList

    #this is for finding
    #this will require the API
    def search(self,queryString,**kwargs):
        wordLength = len(self[0])
        if isinstance(queryString,str):
            # check for lengths and pad accordingly
            
            if len(queryString) > wordLength:
                return False
            while len(queryString) < wordLength:
                queryString += ' '
                
            queryString = NormCipherString(self.apiContext,queryString,keyRange=200)
            
        
        # make sure we have a normCipherString now
        if not isinstance(queryString,NormCipherString):
            return False
        
        tempList = self.vert_merge(queryString)
        
        tempMx = tempList.char_equal_mx()
        #print(len(tempMx))
        #tempList.helper = AnalyticsHelper(self.apiContext,temp_mx,tempList.colMaxChars)

        indexMatches = []
        #return tempMx
        # check equivalence

        for i in range(wordLength):
            if i == 0:
                for j in range(self.length):
                    if tempMx[-1*wordLength][j*wordLength] == 1:
                        indexMatches.append(j)
                #print(indexMatches)
            else:
                for match in indexMatches:
                    if tempMx[-1*wordLength+i][match*wordLength+i] == 1:
                        pass
                    else:
                        indexMatches.remove(match)
        
        if indexMatches == []:
            return False
        return indexMatches #indices of occurrence
    
    #first attempt at computing a levenshtein distance for entity detection purposes
    def levenshtein(self):

        adjMx = self.char_equal_mx()
        word_length = int(len(adjMx[0])/len(self))
        levenMx = np.zeros((len(self),len(self)))
        for i in range(len(self)):
            for j in range(len(self)):
                word_dist = np.zeros((len(self[i])+1,len(self[j])+1))
                for u in range(1,len(self[i])+1):
                    word_dist[u][0] = u
                for v in range(1,len(self[j])+1):
                    word_dist[0][v] = v
                for ii in range(1,len(self[i])+1):
                    for jj in range(1,len(self[j])+1):
                        subPenalty = 1 if adjMx[(i*word_length+ii-1)][(j*word_length+jj-1)] == 0 else 0
                        word_dist[ii][jj] = min(word_dist[ii-1][jj]+1,word_dist[ii][jj-1]+1,word_dist[ii-1][jj-1]+subPenalty)
                levenMx[i][j] = word_dist[len(self[i])][len(self[j])]

            return levenMx
    
    
    
    def custom_equality(self,func):
        
        def getAndRun():
            
            if self.helper == 0:
                temp_mx = self.char_equal_mx()
                self.helper = AnalyticsHelper(self.apiContext,temp_mx,self.colMaxChars)
            analyticsList = []
            for key in range(len(self.cipherListOfList)):
                analyticsList.append(AnalyticsCipherString(self.apiContext,
                                                           self.cipherListOfList[key],
                                                           self.helper,
                                                           self.indicesListOfList[key],
                                                           key*self.helper.offset))
            return func(analyticsList)
                
                
        return getAndRun()
    
    def decrypt(self):
        decryptKeyDict = {t['id']:t['atom_key'] for t in decryption_key(
            self.apiContext,
            json.dumps(flatten_list(self.indicesListOfList))
        )}
        decryptKey = [decryptKeyDict[i] for i in flatten_list(self.indicesListOfList)]
        i=0
        plain = []
        for encryptedWord in self.cipherListOfList:
            plain.append(''.join([chr(t[0]-t[1]) for t in zip(encryptedWord,decryptKey[i:(i+len(encryptedWord))])]))
            i+=len(encryptedWord)
        return plain
    
    def generate_matches(self,other):
        lengthDiff = self.colMaxChars - other.colMaxChars
        if lengthDiff > 0:
            compareOne = self.checksum()
            compareTwo = other.pad(lengthDiff).checksum()
        elif lengthDiff < 0:
            compareOne = self.pad(lengthDiff).checksum()
            compareTwo = other.checksum()
        else:
            compareOne = self.checksum()
            compareTwo = other.checksum()            
            
        matches = []
        hasMatchOne = []
        hasMatchTwo = []
        for i in range(len(compareOne)):
            currentHash = compareOne[i]
            for j in range(len(compareTwo)):
                if compareOne[i]==compareTwo[j]:
                    matches.append((i,j))
                    hasMatchOne.append(i)
                    hasMatchTwo.append(j)
                    
        checkNCL = NormCipherList(
            self.apiContext,
            [self.cipherListOfList[i] for i in hasMatchOne],
            indexData = [self.indicesListOfList[i] for i in hasMatchOne]
        ).vert_merge(
            NormCipherList(
                self.apiContext,
                [other.cipherListOfList[i] for i in hasMatchTwo],
                indexData = [other.indicesListOfList[i] for i in hasMatchTwo]
            )
        )


        matchCheck = checkNCL.char_equal_mx()
        
        wordLength = self.colMaxChars
        compareLength = len(matches)
        newMatches = []
        for i in range(compareLength):
            spotCheck = np.all(np.diagonal(matchCheck[
                (wordLength*i):(wordLength*i+wordLength),
                (compareLength*wordLength+wordLength*i):(compareLength*wordLength+wordLength*i+wordLength)
            ])==1)
            if spotCheck:
                newMatches.append(matches[i])
        return newMatches
      
      
    # this function returns a list of NormCipherLists grouped by value (hash value currently)
    def group_by(self):

        listOfGroupedNCL = []
        indicesAlreadyAdded = []

        if self.helper == 0:
            temp_mx = self.char_equal_mx()
            self.helper = AnalyticsHelper(self.apiContext,temp_mx,self.colMaxChars)

        checksumList = self.checksum()
        for i in range(len(self)):
            value = checksumList[i]
            newCipherListOfList = []
            newIndicesListOfList = []
            if i not in indicesAlreadyAdded:
                indicesAlreadyAdded.append(i)
                for j in range(len(self)):
                    ncs1 = self[i]
                    ncs2 = self[j]
                    if self.helper.checkEquality(ncs1.indicesList,ncs2.indicesList,i*self.colMaxChars,j*self.colMaxChars):
                        newCipherListOfList.append(self[j].cipherList)
                        newIndicesListOfList.append(self[j].indicesList)
                        indicesAlreadyAdded.append(j)
                newNCL = NormCipherList(self.apiContext, newCipherListOfList, newIndicesListOfList)
                listOfGroupedNCL.append(newNCL)

        return listOfGroupedNCL
    
    
    
    
def import_and_encrypt_list(myPlaintext,apiContext,desiredPerms=False,seedString=False,keyRange=32766,permLevel='standard'):
    
    

    columnData = list(myPlaintext)
    myEncodedList = encode_list(columnData)
    myLen = len(myEncodedList)*len(myEncodedList[0])

    #compute length of required encryption key


    #register key data of required length

    if isinstance(seedString,str):
        myKeyLoc = apiContext.get('/statehash/?length=%d&seedString=%s'%(myLen,seedString,))[0]
        #print('basic state')
    else:
        myKeyLoc = apiContext.get('/state/?length='+str(myLen)+'&range='+str(keyRange)
                                  +'&permLevel='+urllib.parse.quote(permLevel))[0]


    #create encryption key for current user

    dataBoundary = [myKeyLoc['minId'],myKeyLoc['maxId']]


    #pull enc key and encrypt

    myKeyGenerator = encryption_key(apiContext,dataBoundary,htmlDebug=False,seedString=seedString)
    #print(myKeyGenerator)
    sortedKeyGenerator = {}
    for atom in myKeyGenerator:
        sortedKeyGenerator[str(atom['id'])] = atom

    currentIndex = myKeyLoc['minId']
    cipherListOfList = []
    indexListOfList = []
    for i in range(len(myEncodedList)):
        cipherList = []
        indexList = []
        for j in range(len(myEncodedList[0])):
            cipherList.append(myEncodedList[i][j]+int(sortedKeyGenerator[str(currentIndex)]['atom_key']))
            indexList.append(currentIndex)
            currentIndex += 1
        cipherListOfList.append(cipherList)
        indexListOfList.append(indexList)        



    return (
        cipherListOfList,
        indexListOfList,
    )