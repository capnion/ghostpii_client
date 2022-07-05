"""
This file contains functions for doing some basic number theory computations 
It also contains standard functions for pulling in stored number theory data like lists of prime numbers
"""

import time
import itertools
import numpy as np

def ext_gcd(aPre,bPre):
    try:
        ans = itersquare_long_cy.ext_gcd_cy(aPre,bPre)
        return {"coefOne":ans[0],"coefTwo":ans[1],"gcd":ans[2] }
    
    except:
        a = int(aPre)
        b = int(bPre)
        s = 0    
        old_s = 1
        t = 1    
        old_t = 0
        r = b
        old_r = a
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t    
        return {"coefOne":old_s,"coefTwo":old_t,"gcd":old_r }  

# the basic modular arithmetic class
class ModArith:
    def __init__(self, residue, modulus):
        self.__residue = residue % modulus
        self.__modulus = modulus
    
    def __hash__(self):
        return self.__residue
        
    def __eq__(self, other): 
        if self.__modulus == other.__modulus:
            if self.__residue == other.__residue: 
                return True
            else:
                return False
        else:
            return "Moduli are not the same!"
        
    def __add__(self, other):
        if self.__modulus == other.__modulus:
            return ModArith((self.__residue + other.__residue) % self.__modulus,self.__modulus)
        else:
            return ModArith(0,1)
        
    def __mul__(self, other):
        if self.__modulus == other.__modulus:
            return ModArith((self.__residue * other.__residue) % self.__modulus,self.__modulus)
        else:
            return ModArith(0,1)
        
    def residue(self):
        return self.__residue
        
    def modulus(self):
        return self.__modulus        
        
    def twokth(self,k):
        prod = self
        
        for i in range(k):
            prod = prod*prod
            
        return prod
        
    def pow_fast(self,expo):
        #first try the C optimized code
        
        try :
            if self.residue() == 0:
                return ModArith(0,self.__modulus)
            else:
                return ModArith(itersquare_long_cy.c_pow_cy(self.__residue,expo,self.__modulus),self.__modulus)  
        #if C code doesn't work, revert to python
        except :
            result = ModArith(1,self.__modulus)
            x = self
            expoRun = expo 

            while expoRun > 0:
                if expoRun % 2 > 0:
                    result = result * x
                    expoRun = expoRun - 1
                x = x * x
                expoRun = expoRun / 2
            return result
    
    
    def inverse(self):
        euclData = ext_gcd(self.__residue,self.__modulus)
        if euclData['gcd']!=1:
            return ModArith(0,1)
        else:
            return ModArith(euclData['coefOne'],self.__modulus)
        
    def __str__(self):
        return "ModArith("+str(self.__residue)+","+str(self.__modulus)+")"

def pow_no_of(base,power,modulus):
    try:
        return itersquare_long_cy.pow_no_of_cy(base,power,modulus)
    except:
        result = base
        for i in range(power-1):
            result = (result * base) % modulus
        
        return result

# 0:4 ind_one,ind_two,row_base,row_prime,
# 4:7 square_coeff_one,lin_coeff_one,const_coeff_one
# 7:10 square_coeff_two,lin_coeff_two,const_coeff_two
def polyn_comp_prod(cursorRow,cipherInt,modulus):

    square = ModArith(cursorRow['square_coeff'],modulus).pow_fast(pow_no_of(cipherInt,2,(modulus-1)))
    linear = ModArith(cursorRow['lin_coeff'],modulus).pow_fast(cipherInt)
    constant = ModArith(cursorRow['const_coeff'],modulus)
    
    return square*linear*constant

#speed kills
#this is the good one
def compute_raw_links_c_poly_flat(ciphertextFlat,linkColumnCursor):
    #clock it
    start = time.time()
    # initialize the array to receive the matching data
    affinitiesFlat = []
    equivClass = []
    # use the cursor to iterate over the rows of the query
    for s in zip(ciphertextFlat,linkColumnCursor):
        equivClass.append(polyn_comp_prod(s[1],s[0],s[1]['prime']))
    for indTup in itertools.product(range(len(ciphertextFlat)),range(len(ciphertextFlat))): 
        #check equality of the computed comparison product with that from the query
        if equivClass[indTup[0]] == equivClass[indTup[1]]:
            affinitiesFlat.append(1)
        else:
            affinitiesFlat.append(0)
                
    outputArray = np.array(affinitiesFlat)
    outputArray.shape = (len(ciphertextFlat),len(ciphertextFlat))
    #print runtime
    print(time.time() - start)
            
    return outputArray

