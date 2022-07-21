# basic modules
import numpy as np
import pandas as pd
import json
from sqlalchemy import *
from copy import deepcopy
import urllib.parse

#a tapas of additional scientific computing 
from scipy.spatial import distance

#capnion submodules

from ..encoding import *
from ..ciphertext import *
from ..num_theory_toolbox import *
from ..db_toolbox import *
from ..polynomial import *

from .norm_cipher_list import *
from .norm_cipher_string import *
from .norm_cipher_quant import *


#this is a list of lists of data intended emulate a pandas data frame
class NormCipherFrame:

    def __init__(self,apiContext,cipherListOfListOfList,indexData=False,dataTypes=False,keyRange=2000,allFloat=False,permLevel='standard'):
        #get list of group elements
        #the rawest version of the underlying data is a list of list of integers
        self.apiContext = apiContext
        self.pure = False
        if isinstance(permLevel,dict):
            permLevel = json.dumps(permLevel)
        self.permLevel = permLevel
        
        if isinstance(cipherListOfListOfList,pd.core.frame.DataFrame): #given a pandas data frame
            if not indexData: #presume the frame is plaintext
                
                self.dataTypes=[]
                for entry in cipherListOfListOfList.dtypes:
                    if entry == np.dtype('float64'):
                        self.dataTypes.append('float')
                    elif entry == np.dtype('int64') and not allFloat:
                        self.dataTypes.append('int')
                    elif entry == np.dtype('int64') and allFloat:
                        self.dataTypes.append('float')
                    elif entry == np.dtype('object'):
                        self.dataTypes.append('string')
                    else:
                        raise Exception('unknown data type')
                importData = import_and_encrypt2(
                    cipherListOfListOfList,
                    self.apiContext,
                    self.dataTypes,
                    seedString=False,
                    keyRange=keyRange,
                    allFloat=allFloat,
                    permLevel = permLevel
                )  
                self.cipherListOfListOfList = importData[0]
                indexData = importData[1]
                self.pure = True
                
            else: #presume the frame is ciphertext
                self.cipherListOfListOfList = imp_dec_encrypted_frame(cipherListOfListOfList,False)[0]
        elif isinstance(cipherListOfListOfList,list): #given a proper list of lists
            if not indexData: #assume the list is plaintext
                print('add, although this scenario does not come up much')
            else: #presume the list is ciphertext
                if isinstance(cipherListOfListOfList[0][0][0],int) or isinstance(cipherListOfListOfList[0][0][0],float): 
                    #directly given the encoded cipher integers
                    self.cipherListOfListOfList = cipherListOfListOfList
                    self.dataTypes = dataTypes
                else: #decode string data to obtain ciphertext integers
                    self.cipherListOfListOfList = [
                        [decode_ciphertext(cipher,proc_standard_decode) for cipher in listOfList] 
                        for listOfList in cipherListOfListOfList
                    ]
        else:
            print('data type not recognized')
                                         
        self.listOfColMaxChars = [len(listOfList[0]) for listOfList in self.cipherListOfListOfList] #assumes same length
        self.rows = len(self.cipherListOfListOfList[0])
        self.cols = len(self.cipherListOfListOfList) 
        self.lists = [i for i in range(self.cols)]
        
                                         
        if isinstance(indexData,int):
            self.indicesListOfListOfList = [] 
            i=indexData
            for cipherListOfList in self.cipherListOfListOfList:                             
                indicesListOfList = []                         
                for cipherList in cipherListOfList:
                    indicesListOfList.append(list(range(i,i+len(cipherList))))
                    i+=len(cipherList)
                self.indicesListOfListOfList.append(indicesListOfList)
        else:
            self.indicesListOfListOfList = indexData 
        
    def __len__(self):
        return self.cols

    def __getslice__(self, start, stop):
        return NormCipherFrame(
            self.apiContext,
            self.cipherListOfListOfList[slice(start,stop)],
            indexData = self.indicesListOfListOfList[slice(start,stop)],
            dataTypes = self.dataTypes[slice(start,stop)]
        )

    #approximating a list of strings, so getting an item should give the normcipherstring
    def __getitem__(self, key):
        if isinstance(key, slice):
            return NormCipherFrame(
                self.apiContext,
                self.cipherListOfListOfList[key],
                indexData = self.indicesListOfListOfList[key],
                dataTypes=self.dataTypes[key]
            )
        else:
            if isinstance(self.lists[key],int):
                if self.dataTypes[key] == 'string':
                    ncl = NormCipherList(
                        self.apiContext,
                        self.cipherListOfListOfList[key],
                        indexData = self.indicesListOfListOfList[key]
                        )
                    self.lists[key] = ncl
                    return ncl
                elif self.dataTypes[key] == 'int' :
                    ncq = NormCipherQuant(
                        self.apiContext,
                        [self.cipherListOfListOfList[key][i][0] for i in range(self.rows)],
                        indexData = [self.indicesListOfListOfList[key][i][0] for i in range(self.rows)],
                        floatData = False
                    )
                    self.lists[key]=ncq
                    return ncq
                else:
                    ncq = NormCipherQuant(
                        self.apiContext,
                        [self.cipherListOfListOfList[key][i][0] for i in range(self.rows)],
                        indexData = [self.indicesListOfListOfList[key][i][0] for i in range(self.rows)],
                        floatData = True
                    )
                    self.lists[key]=ncq
                    return ncq
            else:
                return self.lists[key]
        
    def __iter__(self):
        for i in range(len(self.cipherListOfListOfList)):
            yield self[i]
            
    def group_by(self,colNum):
        listOfGroupedNCF = []
        indicesAlreadyAdded = []
        colToSplit = self[colNum]

        temp_mx = self[colNum].char_equal_mx()
        colToSplit.helper = AnalyticsHelper(self.apiContext,temp_mx,colToSplit.colMaxChars)

        checksumList = colToSplit.checksum()
        for i in range(len(colToSplit)):
            newCipherFrame = None
            value = checksumList[i]
            newCipherListOfList = []
            newIndicesListOfList = []
            if i not in indicesAlreadyAdded:
                indicesAlreadyAdded.append(i)
                
                for j in range(len(colToSplit)):
                    ncs1 = colToSplit[i]
                    ncs2 = colToSplit[j]
                    if colToSplit.helper.checkEquality(ncs1.indicesList,
                                                       ncs2.indicesList,
                                                       i*colToSplit.colMaxChars,
                                                       j*colToSplit.colMaxChars):
                        if newCipherFrame is not None:
                            newCipherFrame = newCipherFrame.vert_merge(self.vert_slice([j]))
                        else:
                            newCipherFrame = self.vert_slice([j])
                        indicesAlreadyAdded.append(j)
                listOfGroupedNCF.append(newCipherFrame)

        return listOfGroupedNCF
            
    def horiz_merge(self, other):
        if isinstance(other, NormCipherFrame):
            return NormCipherFrame(
                self.apiContext,
                self.cipherListOfListOfList+other.cipherListOfListOfList,
                indexData = self.indicesListOfListOfList+other.indicesListOfListOfList,
                dataTypes = self.dataTypes + other.dataTypes
            )
        elif isinstance(other,NormCipherList):
            newCipherList = deepcopy(self.cipherListOfListOfList)
            newCipherList.append(other.cipherListOfList)
            newIndicesList = deepcopy(self.indicesListOfListOfList)
            newIndicesList.append(other.indicesListOfList)
            newDataTypes = deepcopy(self.dataTypes)
            newDataTypes.append('string')
            return NormCipherFrame(
                    self.apiContext,
                    newCipherList,
                    indexData = newIndicesList,
                    dataTypes = newDataTypes
                    )
        else:
            newCipherList = deepcopy(self.cipherListOfListOfList)
            newCipherList.append([[num] for num in other.cipherList])
            newIndicesList = deepcopy(self.indicesListOfListOfList)
            newIndicesList.append([[index]for index in other.indicesList])
            newDataTypes = deepcopy(self.dataTypes)
            if other.floatData:
                newDataTypes.append('float')
            else:
                newDataTypes.append('int')
            return NormCipherFrame(
                    self.apiContext,
                    newCipherList,
                    indexData = newIndicesList,
                    dataTypes = newDataTypes
                    )
            
    
    def vert_merge(self,other):
        return NormCipherFrame(
            self.apiContext,
            [
                self.cipherListOfListOfList[i]+other.cipherListOfListOfList[i] 
                for i in range(len(self.cipherListOfListOfList))
            ],
            indexData = [
                self.indicesListOfListOfList[i]+other.indicesListOfListOfList[i]
                for i in range(len(self.indicesListOfListOfList))
            ],
            dataTypes = self.dataTypes
        )        
    
    def vert_slice(self,rowList):
        return NormCipherFrame(
            self.apiContext,
            [
                [cipherListOfList[i] for i in rowList]
                for cipherListOfList in self.cipherListOfListOfList
            ],
            indexData = [
                [indicesListOfList[i] for i in rowList]
                for indicesListOfList in self.indicesListOfListOfList
            ],
            dataTypes=self.dataTypes
        )
    
    def merge(self,other,colIndexTuple,how='inner'):
        #get the matches on the original data
        myMatches = self[colIndexTuple[0]].generate_matches(other[colIndexTuple[1]])
        if how=='inner':
            #return appropriate entries in a horizontally merged NCF
            return self.vert_slice([t[0] for t in myMatches]).horiz_merge(
                other.vert_slice([t[1] for t in myMatches])
            )
        if how=='left':
            #right frame with an added empty row
            nullOther = other.vert_merge(NormCipherFrame(other.apiContext,pd.DataFrame([[' '*i for i in other.listOfColMaxChars]])))
            #what are the unmatched entries on the left
            missing = [(i,nullOther.rows-1) for i in range(self.rows) if i not in [tup[0] for tup in myMatches]]
            #add matches for unmatched rows onto the final empty row
            myMatches = myMatches + missing
            myMatches.sort(key=lambda t:t[0])
            #return appropriate entries in a horizontally merged NCF
            return self.vert_slice([t[0] for t in myMatches]).horiz_merge(
                nullOther.vert_slice([t[1] for t in myMatches])
            )
        if how=='right':
            #left frame with an added empty row
            nullSelf = self.vert_merge(NormCipherFrame(self.apiContext,pd.DataFrame([[' '*i for i in self.listOfColMaxChars]])))
            #what are the unmatched entries on the right
            missing = [(nullSelf.rows-1,i) for i in range(other.rows) if i not in [tup[1] for tup in myMatches]]
            #add matches for unmatched rows onto the final empty row
            myMatches = myMatches + missing
            myMatches.sort(key=lambda t:t[1])
            #return appropriate entries in a horizontally merged NCF
            return nullSelf.vert_slice([t[0] for t in myMatches]).horiz_merge(
                other.vert_slice([t[1] for t in myMatches])
            )
        if how=='outer':
            #left frame with an added empty row
            nullSelf = self.vert_merge(NormCipherFrame(self.apiContext,pd.DataFrame([[' '*i for i in self.listOfColMaxChars]])))
            #right frame with an added empty row
            nullOther = other.vert_merge(NormCipherFrame(other.apiContext,pd.DataFrame([[' '*i for i in other.listOfColMaxChars]])))
            #what are the unmatched entries on the left
            missingSelf = [(i,nullSelf.rows-1) for i in range(nullOther.rows) if i not in [tup[0] for tup in myMatches]][:-1]
            #what are the unmatched entries on the right
            missingOther = [(nullOther.rows-1,i) for i in range(nullSelf.rows) if i not in [tup[1] for tup in myMatches]][:-1]
            #add matches for unmatched rows onto the final empty row
            myMatches = myMatches + missingSelf + missingOther
            myMatches.sort(key=lambda t:t[0])
            #return appropriate entries in a horizontally merged NCF
            return nullSelf.vert_slice([t[0] for t in myMatches]).horiz_merge(
                nullOther.vert_slice([t[1] for t in myMatches])
            )
                    
    def lol_of_ciphertext(self,codingData=False):        
        return [self[t].list_of_ciphertext(codingData) for t in range(len(self))]
    
    def frame_of_ciphertext(self,codingData=False):   
        return pd.DataFrame(
            np.transpose(np.array(self.lol_of_ciphertext(codingData))),
            columns=list(range(len(self)))
        )
    
    def metadata(self):
        if self.pure:
            return json.dumps({
                'pure':self.pure,
                'listOfColMaxChars':self.listOfColMaxChars,
                'rows':self.rows,
                'cols':self.cols,
                'bounds':self.indicesListOfListOfList[0][0][0]
            })        
        else:
            return json.dumps({
                'pure':self.pure,
                'listOfColMaxChars':self.listOfColMaxChars,
                'rows':self.rows,
                'cols':self.cols,
                'bounds':(
                    self.indicesListOfListOfList[0][0][0],
                    self.indicesListOfListOfList[0][0][0]+sum(self.listOfColMaxChars)*self.rows
                )
            })
    
    def decrypt(self):
        decryptKeyDict = {t['id']:(t['atom_key'],t['atom_key_inv']) for t in decryption_key(
            self.apiContext,
            json.dumps(flatten_list(flatten_list(self.indicesListOfListOfList)))
        )}
        decryptKey = [decryptKeyDict[i] for i in flatten_list(flatten_list(self.indicesListOfListOfList))]
        i=0
        plainBig = []
        for k in range(len(self.cipherListOfListOfList)):
            encryptedWordList = self.cipherListOfListOfList[k]
            plain = []
            for j in range(len(encryptedWordList)):
                if self.dataTypes[k]=='float':
                    plain.append(encryptedWordList[j][0]-(decryptKey[i][0]+decryptKey[i][1]/32767.0))
                    i+=1
                elif self.dataTypes[k]=='int':
                    plain.append(encryptedWordList[j][0]-decryptKey[i][0])
                    i+=1
                else:        
                    encryptedWord = encryptedWordList[j]
                    plain.append(''.join([chr(t[0]-t[1][0]) for t in zip(encryptedWord,decryptKey[i:(i+len(encryptedWord))])]))
                    i+=len(encryptedWord)
            plainBig.append(plain)
        return plainBig
        
    def to_sql(self,table_name,connection):
        cipherFrame = self.frame_of_ciphertext()
        indexData = self.indicesListOfListOfList
        for column in range(len(indexData)):
            ids_to_append = []
            for entry in indexData[column]:
                ids_to_append.append(entry[0])
            cipherFrame['id{}'.format(column)] = ids_to_append
    
        return cipherFrame.to_sql(table_name,connection)
    
 
    
def import_and_encrypt2(myPlaintext,apiContext,dataTypes,desiredPerms=False,seedString=False,keyRange=32766,allFloat=False,permLevel='standard'):
    
    colIndex = 0
    cipherListOfListOfList = []
    indexListOfListOfList = []
    for (columnName, columnData) in myPlaintext.iteritems():
        #pad, measure, and encode
        if dataTypes[colIndex] == 'string':
            myEncodedList = encode_list(columnData)
            myLen = len(myEncodedList)*len(myEncodedList[0])
        elif dataTypes[colIndex] =='float':
            myEncodedList = [[float(f)] for f in columnData]
            myLen = len(myEncodedList) 
        else:
            myEncodedList = [[int(f)] for f in columnData]
            myLen = len(myEncodedList)
        #print(myEncodedList)
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
        #print(sortedKeyGenerator)
        currentIndex = myKeyLoc['minId']
        cipherListOfList = []
        indexListOfList = []
        for i in range(len(myEncodedList)):
            cipherList = []
            indexList = []
            for j in range(len(myEncodedList[0])):
                if dataTypes[colIndex] == 'float':
                    
                    cipherList.append(myEncodedList[i][j]+int(sortedKeyGenerator[str(currentIndex)]['atom_key'])+int(sortedKeyGenerator[str(currentIndex)]['atom_key_inv'])/32767.0)
                else:
                    cipherList.append(myEncodedList[i][j]+int(sortedKeyGenerator[str(currentIndex)]['atom_key']))
                indexList.append(currentIndex)
                currentIndex += 1
            cipherListOfList.append(cipherList)
            indexListOfList.append(indexList)        
            
        
        cipherListOfListOfList.append(cipherListOfList)
        indexListOfListOfList.append(indexListOfList)
        
        colIndex += 1


    return (
        cipherListOfListOfList,
        indexListOfListOfList,
    )
    
def import_from_db(cryptoContext,table_name,connection):
    meta_df = pd.read_sql_table(table_name,connection)
    meta_df = meta_df.drop('index',axis=1)
    num_rows = meta_df.shape[0]
    num_cols = meta_df.shape[1]//2
    indices = np.zeros((num_cols,num_rows),dtype = int)
    for index,row in meta_df.iterrows():
        for i in range(num_cols):
            indices[i,index] = row['id{}'.format(i)]
    indices_list = indices.tolist()
    for i in range(indices.shape[0]):
        col_length = len(meta_df[str(i)][0])//3
        for j in range(indices.shape[1]):
            indices_list[i][j] = [k for k in range(indices[i][j],indices[i][j]+col_length)]
        meta_df = meta_df.drop('id{}'.format(i),axis=1)
    return NormCipherFrame(cryptoContext,meta_df,indexData=indices_list)