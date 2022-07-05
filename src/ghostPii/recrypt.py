import random
import json

from .db_toolbox import *


def paillier_to_otp(apiContext,paillierEncrypted,paillierKeyID,isSum=False,isFloat=False):
    from .data_structures.norm_cipher_quant import NormCipherQuant
    from .data_structures.paillier_num import PaillierFloat


    length = len(paillierEncrypted)
    
    
    tempOTP_int = random.choices(list(range(1,32767)),k=length)
    
    #pad depending on float/int
    if isFloat:
        tempOTP_frac = random.choices(list(range(1,32767)),k=length)
        encryptedNums = []
        
        for i in range(length):
            newNum = paillierEncrypted[i] + (tempOTP_int[i] + tempOTP_frac[i]/32767.0)
            encryptedNums.append(json.dumps({'cipherTup':newNum.cipherTup, 'c':newNum.c}))
        
    else:
        
        encryptedNums = []
        for i in range(length):

            newNum = paillierEncrypted[i] + tempOTP_int[i]
            encryptedNums.append(json.dumps({'cipherTup':newNum.cipherTup, 'c':newNum.c}))
        
        
    paillierDict = {'keyID':[paillierKeyID],'paillierData':encryptedNums,'isFloat':isFloat,'isSum':isSum}
    #print(paillierDict)
    newCipherData = paillier_convert(apiContext,paillierDict)
    #print(newCipherData)
    
    cipherList = []
    indexList = []

    for i in range(len(newCipherData)):
        if isFloat:
            
            cipherList.append(newCipherData[i]['cipher']-(tempOTP_int[i]+tempOTP_frac[i]/32767.0))
        else:
            cipherList.append(int(newCipherData[i]['cipher']-tempOTP_int[i]))
        indexList.append(newCipherData[i]['keyID'])
    
    return NormCipherQuant(apiContext,cipherList,indexData=indexList,floatData=isFloat)



