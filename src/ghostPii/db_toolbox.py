import time
import requests
import itertools
import json
import datetime 
import random



from IPython.core.display import display, HTML

def id_dict(queryList):
    newDict = {}
    for row in queryList:
        newDict[row['id']] = row
    return newDict

#login using username, password, and headers
#Should delete username and password as they are not used in the verification process
def open_rest_conn(headers,urlBase):
    # api url
    URL = urlBase + '/api-auth/login/'

    client = requests.session()

    # Retrieve the CSRF token first
    client.get(URL,headers=headers,verify=True)  # sets cookie
    if 'csrftoken' in client.cookies:
        # Django 1.6 and up
        csrftoken = client.cookies['csrftoken']
    else:
        # older versions
        csrftoken = client.cookies['csrf']

    login_data = dict(csrfmiddlewaretoken=csrftoken, next='/')
    temp_dict = dict(Referer=URL)
    client.post(URL, data=login_data, headers={**temp_dict,**headers})
    
    return client


def process_enc_stream(encRequest):
    superString = ""
    for t in encRequest:
        superString = superString + t.decode('utf8')

    #print(superString)

    stringDefs = [t.strip('(').strip(')') for t in superString.split("OrderedDict") if len(t)>0]

    myList=[]
    for i in range(len(stringDefs)):
        formatNamespace = {}        
        exec('myTuple = tuple('+stringDefs[i]+')', formatNamespace)
        myList.append(formatNamespace['myTuple'])

    return [{t[0][0]:t[0][1],t[1][0]:t[1][1]} for t in myList]   

#generator version of the above
def enc_generator(encRequest):
    leftoverString = ''
    for t in encRequest:
        stringList = (leftoverString+t.decode('utf8')).split('OrderedDict')
        #new value for the leftover string
        leftoverString = stringList[-1]
        #clean and format "good" strings from the split
        stringDefs = [u.strip('(').strip(')') for u in stringList[:-1] if len(u)>0]
        
        for i in range(len(stringDefs)):
            encNamespace = {}        
            exec('myTuple = tuple('+stringDefs[i]+')', encNamespace)
            tup = encNamespace['myTuple']
            yield {tup[0][0]:tup[0][1],tup[1][0]:tup[1][1]}
            
    encNamespace = {}        
    exec('myTuple = tuple('+leftoverString+')', encNamespace)
    tup = encNamespace['myTuple']
    yield {tup[0][0]:tup[0][1],tup[1][0]:tup[1][1]}

# an object intended to be in play everywhere managing info about the relation to the API
class CryptoContext:
    def __init__(self,headers,targetServer = False):
        if targetServer:
            print('Connecting to %s'%(targetServer,))
            self.urlBase = targetServer
        else:
            self.urlBase = 'https://ghostpii.com/api'
        
        self.client = open_rest_conn(headers,self.urlBase)

        self.headers = headers
        
        self.userInfo = self.client.get(
            self.urlBase+'/users/',
            headers = self.headers,
            verify = True
        ).json()
        
        self.userId = int([userDict['url'].split('/')[-2]  for userDict in self.userInfo][0])
        
        try:
            self.keyInfo = keyInfoPre.json()
        except:
            self.keyInfo = []
        
    def get(self,url,htmlDebug=False): 
    
        currentRequest =  self.client.get(
            self.urlBase + url,
            headers = self.headers,
            verify = True
        )
        if htmlDebug == True:
            
            return display(HTML(currentRequest.text))
        elif '/encrypt/' in url:
            
            return enc_generator(currentRequest)
        else:
            
            try:
                return currentRequest.json()
            except:
                print('json failure')
                print(display(HTML(currentRequest.text)))
            
    def post(self,url,myData):
        return self.client.post(
            self.urlBase + url,
            headers = self.headers,
            verify = True,
            data = myData
        )

#this returns a generator and not a completed object in memory
def encryption_key(apiContext,minMax,htmlDebug=False,seedString=False):
    if isinstance(seedString,str):
        print("Key generated locally from hash")
        return [{'id':t[0],'atom_key':t[1]} for t in zip(range(minMax[0],minMax[1]),string_to_key(seedString,minMax[1]-minMax[0]))]
    else:    
        url = '/staticencrypt/?lower=%d&upper=%d' % (minMax[0],minMax[1],)
        #print(url)
        return apiContext.get(url,htmlDebug)
    
    
def paillier_encryption_key(apiContext,htmlDebug=False,seedString=False):
    
    myKeyLoc = apiContext.get('/paillier-state/?length=1')
    #determine key boundaries
    dataBoundary = [myKeyLoc[0]['minId'],myKeyLoc[0]['maxId']]
    
    url = '/paillier-staticencrypt/?lower=%d&upper=%d' % (dataBoundary[0],dataBoundary[1])
    #print(url)
    return apiContext.get(url,htmlDebug)[0]

def decryption_key(apiContext,indicesJson,htmlDebug=False):
    
    #get the current timestamp
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])

    #post a blob of information about the desired polynomial computation at the given timestamp
    
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":indicesJson,"userhash":timeStamp})
    #print(test.text)
    
    url = '/decrypt/?blobData=%d' % (
        timeStamp,
    )
    #print(url)
    return apiContext.get(url,htmlDebug)

def paillier_decryption_key(apiContext,index,htmlDebug=False):
    
    #get the current timestamp
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])

    #post a blob of information about the desired polynomial computation at the given timestamp
    test = apiContext.post('/blob/', {"assigned_user":apiContext.userId,"keyJSON":json.dumps([index]),"userhash":timeStamp,"enc_type":"Paillier"}
                          )
    #print(test)
    
    url = '/paillier-decrypt/?blobData=%d' % (
        timeStamp,
    )
    #print(url)
    return apiContext.get(url,htmlDebug)[0]

def linking_key(apiContext,indicesJson):
    
    #get the current timestamp
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])

    #post a blob of information about the desired polynomial computation at the given timestamp
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":indicesJson,"userhash":timeStamp})
    print(test)
    
    url = '/recordlink/?blobData=%d' % (
        timeStamp,
    )
    #print(url)    
    return apiContext.get(url)

def recryption_key(apiContext,requestData):
    
    #get the current timestamp
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])

    #post a blob of information about the desired polynomial computation at the given timestamp
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":indicesJson,"userhash":timeStamp})
    #print(test)
    
    url = '/recrypt/?blobData=%d' % (
        timeStamp,
    )
    #print(url)    
    return apiContext.get(url)

def ngram_checksum_key(apiContext,window,wordLength,indicesJson,isFloat=False):
    
    #get the current timestamp
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])

    #post a blob of information about the desired polynomial computation at the given timestamp
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":indicesJson,"userhash":timeStamp})
    #print(test)
    
    #this url
    url = '/ngramview/?win=%d&wordLength=%d&blobData=%d&isFloat=%s' % (
        window,
        wordLength,
        timeStamp,
        isFloat
    )
    return apiContext.get(url)

def polyn_comp_key(apiContext,polyn,polynVars,indicesTupleList,dualListOfList,isFloat=False,paillier=True):
    
    #get the current timestamp
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])
    
    #information about the polynomial to be computed
    polynData = {
        'polyn':polyn,
        'polynVars':polynVars,
        'indicesTupleList':indicesTupleList,
        'dualTupleList':dualListOfList,
        'isFloat':isFloat,
        'paillier':paillier,
    }
    
    
    #post a blob of information about the desired polynomial computation at the given timestamp
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":json.dumps(polynData),"userhash":timeStamp})
    #print(test.text)
    #this url tells the general polynomial endpoint to compute the desired polynomial
    url = '/general/?blobData=%d' % (
        timeStamp,
    )
    
    output = apiContext.get(url)
    #print(output)
    return output

def rand_poly_comp_key(apiContext,polyn,polynVars,indicesTupleList,dualListOfList,isFloat=False,paillier=True):
    
    #get the current timestamp
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])
    
    #information about the polynomial to be computed
    polynData = {
        'polyn':polyn,
        'polynVars':polynVars,
        'indicesTupleList':indicesTupleList,
        'dualTupleList':dualListOfList,
        'isFloat':isFloat,
        'paillier':paillier,
    }
    
    #print(polyn)
    
    #post a blob of information about the desired polynomial computation at the given timestamp
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":json.dumps(polynData),"userhash":timeStamp})
    #print(test.text)
    
    #this url tells the general polynomial endpoint to compute the desired polynomial
    url = '/randomized-poly/?blobData=%d' % (
        timeStamp,
    )
    
    output = apiContext.get(url)
    #print(output)
    return output

def paillier_convert(apiContext,paillierDict):
    
                    
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])
    #print(paillierDict)
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":json.dumps(paillierDict),"userhash":timeStamp})
    #print(test.text)
    
    url = '/paillier-otp/?blobData=%d' % (
        timeStamp,
    )
    
    newCipherData = apiContext.get(url)
    
    return newCipherData
    
def paillier_recrypt(apiContext,paillierDict):
    
                    
    timeStamp = int(str(datetime.datetime.now()).replace(' ','').replace('-','').replace(':','').replace('.','')[0:18])
    test = apiContext.post('/blob/',{"assigned_user":apiContext.userId,"keyJSON":json.dumps(paillierDict),"userhash":timeStamp})
    #print(test.text)
    
    url = '/paillier-recrypt/?blobData=%d' % (
        timeStamp,
    )
    
    newCipherData = apiContext.get(url)
    
    return newCipherData
    
    