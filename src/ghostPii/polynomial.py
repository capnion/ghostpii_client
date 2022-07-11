import sympy as sym
import math
import random
import numpy as np
import json
import time

from .data_structures.paillier_num import PaillierInt, PaillierFloat
from .db_toolbox import *
from .recrypt import paillier_to_otp

def create_polynomial(polyString,inVars):
    polyNamespace = {}
    exec("import sympy as sym", polyNamespace)    
    varList = []
    cList = []
    kList = []
    
    for varNameString in inVars:
        exec("c%s = sym.Symbol('c%s')" % (varNameString,varNameString,), polyNamespace)
        exec("k%s = sym.Symbol('k%s')" % (varNameString,varNameString,), polyNamespace)
        varList.append("c%s" % (varNameString,))
        varList.append("k%s" % (varNameString,))
        cList.append("c%s" % (varNameString,))
        kList.append("k%s" % (varNameString,))
        exec("%s = c%s - k%s" % (varNameString,varNameString,varNameString,), polyNamespace)  # plaintext integer
    
    exec('f='+polyString, polyNamespace)  # plaintext integer
    
    return {'namespace':polyNamespace,'varList':varList,'cList':cList,'kList':kList}

def flatten_nested(nestedTuple,length):
    endList = []
    remain = nestedTuple
    while len(endList)<length:
        new = []
        for t in remain:
            if isinstance(t,int):
                endList.append(t)
            else:
                new = new + list(t)
        remain = new
    return endList

from itertools import product
def all_partial_degrees(maxDegree,nVars):
    if nVars==1:
        for t in range(maxDegree+1):
            yield [t]
    else:
        baseProduct = range(maxDegree+1)
        nVars-=1
        for i in range(nVars):
            baseProduct = product(range(maxDegree+1),baseProduct)
        for t in baseProduct:
            flattenedT = flatten_nested(t,nVars)
            if(sum(flattenedT)<=maxDegree):
                yield flattenedT

def term_count(n,d):
    return int(sum([math.factorial(dd+n-1)/( math.factorial(dd) * math.factorial(n-1)) for dd in range(d+1)]))

def compute_polynomial(polynKey,indicesTupleList,cipherTupleList,polyn,paillier=True):
    #deserialize and reformat our key
    formattedKey = json.loads(polynKey[0]['keyJSON'])['monomialData']
    #list of client side ciphertext variables, need a count
    cipherVars = polyn['cList']
    #print(cipherVars)
    numberOfVars = len(cipherVars)
    #get the total degree of f
    try:
        f = polyn['namespace']['f']
        degree = sym.Poly(f).total_degree()
    except:
        degree = polyn['degree']
    if paillier:
        myPaillier = json.loads(polynKey[0]['keyJSON'])['paillierData']

        publicKey = {'n':myPaillier['n'],'g':myPaillier['g'],'id':myPaillier['id']}
        #print(publicKey)
        #temporary test Paillier computation

        formattedKeyEncrypted = {
            s:{t:PaillierFloat(publicKey,formattedKey[s][t],c=0) for t in formattedKey[s].keys()} 
            for s in formattedKey.keys()
        }
    else:
        #print(formattedKey)
        
        formattedKeyEncrypted = formattedKey
    
    values = []
    
    for fiber in zip(indicesTupleList,cipherTupleList):
        
        position=0
        currentIndices = fiber[0]
        currentCiphertext = fiber[1]
        currentKeyData = formattedKeyEncrypted[','.join([str(t) for t in currentIndices])]
        cipherMonomials = {}
        cipherMonomialStrings = []
        for exponentTuple in all_partial_degrees(degree,numberOfVars):
            #print('\n',exponentTuple,currentKeyData,currentCiphertext)
            monomial = 1
            cipherMonomialString = ''
            for i in range(len(exponentTuple)):
                exponent = exponentTuple[i]
                #construct a dictionary key for the current monomial
                currentVar = cipherVars[i]
                
                cipherMonomialString = cipherMonomialString + currentVar*exponent
                #take appropriate power of the derivative
                monomial = monomial*(currentCiphertext[i]**exponent)
            cipherMonomials[cipherMonomialString] = monomial
            cipherMonomialStrings.append(cipherMonomialString)
        if paillier:
            innerProductSum = PaillierFloat(publicKey,0,fromPlain=True,c=0)
            for monString in cipherMonomialStrings:
                currentProduct = currentKeyData[monString]*cipherMonomials[monString]

                innerProductSum = innerProductSum + currentProduct


            values.append(innerProductSum)
            
        else:
            
            values.append(sum([currentKeyData[monString]*cipherMonomials[monString] for monString in cipherMonomialStrings]))
        
    
    if paillier:
        return values,publicKey
    else:
        return values,None

def full_polynomial_compute(apiContext,polyString,variables,myIndices,myCiphers,isFloat,isSum=False,paillier=True,outPlain=False):
    
    if 'random' in polyString:
        myPoly = polyString
    else:
        myPoly = create_polynomial(polyString, variables)
    start = time.time()
    myKey = polyn_comp_key(apiContext,polyString,variables,myIndices,0,isFloat = isFloat,paillier=paillier)
    #print(myKey)
    end = time.time()
    
    paillier = json.loads(myKey[0]['keyJSON'])['paillier']
    #print(paillier)
    if 'random' in polyString:
        myPoly = json.loads(myKey[0]['keyJSON'])['poly']
        #print(myPoly)
    ans,paillierKey = compute_polynomial(myKey, myIndices, myCiphers, myPoly,paillier=paillier)
    end2 = time.time()
    
    
    if paillier:
        if isSum:
            ans = sum(ans)
            ncq = paillier_to_otp(apiContext,[ans],paillierKey['id'],isSum=isSum,isFloat=isFloat)
            end3 = time.time()
            
            if outPlain:
                return ncq.decrypt()[0]
            else:
                return ncq
        if outPlain:
            ncq = paillier_to_otp(apiContext,ans,paillierKey['id'],isSum=isSum,isFloat=isFloat)
            return ncq.decrypt()
            
        else:
            ncq = paillier_to_otp(apiContext,ans,paillierKey['id'],isSum=isSum,isFloat=isFloat)
            return ncq
    else:
        if outPlain:
            #print(ans)
            if isSum:
                return sum(ans)
            else:
                return ans
        else:
            from src.ghostPii.data_structures.norm_cipher_quant import NormCipherQuant
            if isSum:
                return NormCipherQuant(apiContext,[sum(ans)],fromPlain=True)
            else:
                return NormCipherQuant(apiContext,ans,fromPlain=True)
    end3 = time.time()

    return ncq
    
    