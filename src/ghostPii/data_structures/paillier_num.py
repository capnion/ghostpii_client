from random import randint
import math
import json
from json import JSONEncoder
import numpy as np
import time
from ..db_toolbox import *

class PaillierInt():
    def __init__(self,pubKeyPair,cipher,fromPlain=False):
        if fromPlain == True:
            #in this scenario cipher is actually a plaintext integer
           
            self.n = pubKeyPair['n']
            self.n2 = pow(self.n,2)
            self.g = pubKeyPair['g']
            self.pubKeyPair = pubKeyPair
            
                     
                
            #final encryption step
            self.cipher = (pow(self.g,cipher,self.n2)*pow(randint(1,self.n),self.n,self.n2))%self.n2
            
                                      
        else:
                                      
            self.cipher = cipher
            self.n = pubKeyPair['n']
            self.g = pubKeyPair['g']
            self.n2 = pow(self.n,2)
            self.pubKeyPair = pubKeyPair
            
        
        
    def L(self,x):
        return (x-1)//self.n
    
    def __len__(self):
        return 1
        
    def __str__(self):
        return str(self.cipher)
    
    def __hash__(self):
        return sum([(t**2 % 10000) for t in cipherList]) % 10000
    
    def __add__(self,other):
        if type(other) is int:
            res = (self.cipher*pow(self.g,other,self.n2))%self.n2
            newNum = PaillierInt(pubKeyPair = self.pubKeyPair, cipher=res)
            return newNum
        elif type(other) is PaillierInt:
            res = (self.cipher*other.cipher) % self.n2
            newNum = PaillierInt(pubKeyPair = self.pubKeyPair, cipher=res)
            return newNum
        else:
            raise Exception("Can only add an int or another PaillierInt")
            
    def __radd__(self,other):
        if type(other) is int:
            res = (self.cipher*pow(self.g,other,self.n2))%self.n2
            newNum = PaillierInt(pubKeyPair = self.pubKeyPair, cipher=res)
            return newNum
        elif type(other) is PaillierInt:
            res = (self.cipher*other.cipher) % self.n2
            newNum = PaillierInt(pubKeyPair = self.pubKeyPair, cipher=res)
            return newNum
        else:
            raise Exception("Can only add an int or another PaillierInt")
            
            
    def __sub__(self,other):
        if type(other) is PaillierInt:
            res = (self.cipher * pow(other.cipher,-1,self.n2)) %self.n2
            newNum = PaillierInt(pubKeyPair = self.pubKeyPair, cipher=res)
            return newNum
        else:
            raise Exception("Can only subtract another PaillierInt")
            
        
    def __mul__(self,other):
        if type(other) is int:
            if other == 0:
                newNum = PaillierInt(self.pubKeyPair, 0,fromPlain=True)
            elif other == 1:
                newNum = PaillierInt(self.pubKeyPair, 0,fromPlain=True)+PaillierInt(self.pubKeyPair, self.cipher)
            else:
                res = pow(self.cipher,other,self.n2)
                newNum = PaillierInt(pubKeyPair = self.pubKeyPair, cipher=res)
            return newNum
        
    def __rmul__(self,other):
        if type(other) is int:
            if other == 0:
                newNum = PaillierInt(self.pubKeyPair, 0,fromPlain=True)
            elif other == 1:
                newNum = PaillierInt(self.pubKeyPair, 0,fromPlain=True)+PaillierInt(self.pubKeyPair, self.cipher)
            else:
                res = pow(self.cipher,other,self.n2)
                newNum = PaillierInt(pubKeyPair = self.pubKeyPair, cipher=res)
            return newNum
        
    def unsigned_decrypt(self,keyLambda,keyMu):
        
        plaintext = (self.L(pow(self.cipher,keyLambda,self.n2)) * keyMu) % self.n
        
        return plaintext
    
    def decrypt(self,keyLambda,keyMu):
        
        dec = self.unsigned_decrypt(keyLambda,keyMu)
        ans = ((dec + self.n//2)%self.n) - self.n//2
        return ans
    
    def ciphertext(self):
        
        return self.cipher
    
    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)
            
        
        
class PaillierFloat():
    def __init__(self,pubKeyPair,cipherTup,fromPlain=False,c=0,cIncrement = 20,r=False):
        self.large_num = 10**40
        if fromPlain:
            
            plain = cipherTup
            floor = math.floor(plain)
            res = plain-floor
            res = math.floor(res*self.large_num)
            self.n = pubKeyPair['n']
            self.n2 = pow(self.n,2)
            self.g = pubKeyPair['g']
            self.pubKeyPair = pubKeyPair
            
            plain_tup = (floor,res)
            
            self.cipherTup = self.encrypt_tuple(plain_tup,r)
            self.c = c
            self.cIncrement = cIncrement
            
            
        else:
            
            self.n = pubKeyPair['n']
            self.n2 = pow(self.n,2)
            self.g = pubKeyPair['g']
            self.pubKeyPair = pubKeyPair
            self.cipherTup = cipherTup
            self.c = c
            self.cIncrement = cIncrement
            
            
    def L(self,x):
        return (x-1)//self.n
    
    def encrypt_tuple(self,plain_tup,r=False):
        start_random = time.time()
        if r:
            r = r
        else:
            r = pow(randint(1,self.n),self.n,self.n2)
       
        new_g = pow(self.g,plain_tup[0],self.n2)
        enc_val1 = (new_g*r)%self.n2
        enc_val2 = (pow(self.g,plain_tup[1],self.n2)*r)%self.n2
        
        return (enc_val1,enc_val2)
    
    def unsigned_single_decrypt(self,single_val,keyLambda,keyMu):
        
        plaintext = (self.L(pow(single_val,keyLambda,self.n2)) * keyMu) % self.n
        
        return plaintext
    
    def single_decrypt(self,single_val,keyLambda,keyMu):
        
        dec = self.unsigned_single_decrypt(single_val,keyLambda,keyMu)
        ans = ((dec + self.n//2)%self.n) - self.n//2
        
        return ans
    
    def decrypt(self,keyLambda,keyMu):
        
        base = self.single_decrypt(self.cipherTup[0],keyLambda,keyMu)
        frac = self.single_decrypt(self.cipherTup[1],keyLambda,keyMu)
        
        return (base + frac/self.large_num)/(10**self.c)
    
    def recrypt(self,apiContext):
        tempOTP_int = random.randint(1,32767)
        tempOTP_frac = random.randint(1,32767)
        
        
        newNum = self + tempOTP_int 
        encryptedNums=[newNum.toJson()]
        isFloat = True
        
        paillierDict = {'keyID':[self.pubKeyPair['id']],'paillierData':encryptedNums,'isFloat':isFloat}
        newData = paillier_recrypt(apiContext,paillierDict)[0]
        #print(newData)
        
        self.cipherTup = (int(newData['cipherInt']),int(newData['cipherFrac']))
        
        self.cipherTup = (PaillierFloat(self.pubKeyPair,self.cipherTup)  - tempOTP_int).cipherTup
        self.c = 0
        return True
        
        
    
    def single_add(self, num1,num2):
        return (num1*num2)%self.n2
        
        
        
    # potential overflow with frac?
    # probably won't matter with our range but might be possible
    def __add__(self,other):
        if type(other) is PaillierFloat:
            if self.c > other.c:
                cdiff = self.c-other.c
                new_base = self.single_add(self.cipherTup[0],self.single_mult(other.cipherTup[0],10**cdiff))
                new_frac = self.single_add(self.cipherTup[1],self.single_mult(other.cipherTup[1],10**cdiff))
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
            elif other.c > self.c:
                cdiff = other.c-self.c
                new_base = self.single_add(self.single_mult(self.cipherTup[0],10**cdiff),other.cipherTup[0])
                new_frac = self.single_add(self.single_mult(self.cipherTup[1],10**cdiff),other.cipherTup[1])
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=other.c,cIncrement=self.cIncrement)
            else:
                new_base = self.single_add(self.cipherTup[0],other.cipherTup[0])
                new_frac = self.single_add(self.cipherTup[1],other.cipherTup[1])
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
        elif type(other) is int or type(other) is float:
            enc_other = PaillierFloat(self.pubKeyPair,other*(10**self.c),fromPlain=True,cIncrement=self.cIncrement)
            new_base = self.single_add(self.cipherTup[0],enc_other.cipherTup[0])
            new_frac = self.single_add(self.cipherTup[1],enc_other.cipherTup[1])
            return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
        else:
            raise Exception("Can only add an int, float, or another PaillierFloat")
            
    def __radd__(self,other):
        if type(other) is PaillierFloat:
            if self.c > other.c:
                cdiff = self.c-other.c
                new_base = self.single_add(self.cipherTup[0],self.single_mult(other.cipherTup[0],10**cdiff))
                new_frac = self.single_add(self.cipherTup[1],self.single_mult(other.cipherTup[1],10**cdiff))
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
            elif other.c > self.c:
                cdiff = other.c-self.c
                new_base = self.single_add(self.single_mult(self.cipherTup[0],10**cdiff),other.cipherTup[0])
                new_frac = self.single_add(self.single_mult(self.cipherTup[1],10**cdiff),other.cipherTup[1])
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=other.c,cIncrement=self.cIncrement)
            else:
                new_base = self.single_add(self.cipherTup[0],other.cipherTup[0])
                new_frac = self.single_add(self.cipherTup[1],other.cipherTup[1])
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
        elif type(other) is int or type(other) is float:
            enc_other = PaillierFloat(self.pubKeyPair,other*(10**self.c),fromPlain=True,cIncrement=self.cIncrement)
            new_base = self.single_add(self.cipherTup[0],enc_other.cipherTup[0])
            new_frac = self.single_add(self.cipherTup[1],enc_other.cipherTup[1])
            return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
        else:
            raise Exception("Can only add an int, float, or another PaillierFloat")
            
            
    def __sub__(self,other):
        
        neg_other = other * -1
        
        return PaillierFloat(self.pubKeyPair,self.cipherTup,c=self.c,cIncrement=self.cIncrement) + neg_other
            
        
    def single_mult(self,enc_num,scalar):
        
        res = pow(enc_num,scalar,self.n2)
            
        return res
        
        
    def __mul__(self,other):
        
        if type(other) is int:
            if other == 0:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)
            elif other == 1:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)+PaillierFloat(self.pubKeyPair,self.cipherTup,c=self.c,cIncrement=self.cIncrement)
            else:
                new_base = self.single_mult(self.cipherTup[0],other)
                new_frac = self.single_mult(self.cipherTup[1],other)
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
            
        elif type(other) is float or type(other) is np.float64:
            if other == 0:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)
            elif other == 1:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)+PaillierFloat(self.pubKeyPair,self.cipherTup,c=self.c,cIncrement=self.cIncrement)
            else:
                other_base = math.floor(other*(10**self.cIncrement))
                new_base = self.single_mult(self.cipherTup[0],other_base)
                new_frac = self.single_mult(self.cipherTup[1],other_base)
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c+self.cIncrement,cIncrement=self.cIncrement)
                
                
            
        else:
            print(other)
            raise Exception("only int and float multiplication are allowed with PaillierFloat")
        
    def __rmul__(self,other):
        
        if type(other) is int:
            if other == 0:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)
            elif other == 1:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)+PaillierFloat(self.pubKeyPair,self.cipherTup,c=self.c,cIncrement=self.cIncrement)
            else:
                new_base = self.single_mult(self.cipherTup[0],other)
                new_frac = self.single_mult(self.cipherTup[1],other)
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c,cIncrement=self.cIncrement)
            
        elif type(other) is float:
            if other == 0:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)
            elif other == 1:
                return PaillierFloat(self.pubKeyPair,0,fromPlain=True,cIncrement=self.cIncrement)+PaillierFloat(self.pubKeyPair,self.cipherTup,c=self.c,cIncrement=self.cIncrement)
            else:
                other_base = math.floor(other*(10**self.cIncrement))
                new_base = self.single_mult(self.cipherTup[0],other_base)
                new_frac = self.single_mult(self.cipherTup[1],other_base)
                return PaillierFloat(self.pubKeyPair,(new_base,new_frac),c=self.c+self.cIncrement,cIncrement=self.cIncrement)
                
                
            
        else:
            raise Exception("only int and float multiplication are allowed with PaillierFloat")
            
    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)
    
    
