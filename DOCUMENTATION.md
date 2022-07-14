## Quick Links
- [NormCipherFrame](#normcipherframe)
- [NormCipherList](#normcipherlist)
- [NormCipherString](#normcipherstring)
- [NormCipherQuant](#normcipherquant)
- [NormCipherNum](#normciphernum)
- [CryptoContext](#cryptocontext)
- [Permissions](#permissions)

# NormCipherFrame

**class** NormCipherFrame( **myContext, cipherListOfListOfList,
indexData=False,fromPlain=False,dataTypes=False,keyRange=2000,allFloat=False,permLevel
='standard'** )

This class mimics a pandas DataFrame except it stores encrypted data instead of plaintext. It can be
sliced and/or indexed similarly.

## Parameters

```
● myContext -- CryptoContext
This argument accepts a CryptoContext object that is used for authentication/communication
with the API
● cipherListOfListOfList -- Pandas dataframe or 3D listof ciphertext integers
Almost always this argument is a plaintext pandas dataframe unless you are doing some
custom frame of already encrypted data
● indexData -- None or 3D list of index integers
Almost always ommitted as an argument unless you are doing some custom frame of
already encrypted data
● fromPlain -- None or True
Indicates whether the data needs encryption
● dataTypes -- None or a list of types correspondingto each column
Almost always ommitted as an argument unless you already have a different encrypted
frame. We will determine data types at runtime if given plaintext
● keyRange -- None or int
This argument specifies the range of values to use for one time pad keys, smaller numbers
will provide increased accuracy (particularly for numerical computations) at the cost of
security
● allFloat -- None or True
This specifies if all numbers in the frame should be padded with floating point keys or if they
should be padded according to their basic data type (int vs float)
● permLevel -- string
This specifies the level of permissions granted to a newly encrypted frame
```
## Methods

```
● horiz_merge ( otherNCF )
This method accepts another NormCipherFrame or NormCipherList and performs a
horizontal merge
● vert_merge ( otherNCF )
This method accepts another NormCipherFrame and performs a vertical merge
● frame_of_ciphertext ()
Accepts no arguments and returns a pandas dataframe of printable ciphertext (will not work if
you have floating point numbers in the frame)
● metadata ()
Accepts no arguments and returns a Json Dict of metadata useful for sending encrypted data
to others
● decrypt ()
Accepts no arguments and returns the decrypted dataframe. Will raise an error if you lack
the permissions for this operation
```
## Attributes

```
● rows
Number of rows in this NCF
● cols
Number of columns in this NCF
● listOfColMaxChars
Length of strings in each column
● cipherListOfListOfList
3D list of ciphertext integers
● indicesListOfListOfList
3D list of index integers
● dataTypes
a list of strings indicating what type of data is stored in each column
```
## Supported Operations

```
● len( )
● [ i ] (indexing)
● [ i : j ] (slicing)
● for encryptedList in NormCipherFrame (iteration)
```

# NormCipherList

**class** NormCipherList( **myContext, cipherListOfList,
indexData=False,fromPlain=False,seedString=False,keyRange=2000,permLevel='standard'** )

This class mimics a list object with some additional methods and features.

## Parameters

```
● myContext -- CryptoContext
This argument accepts a CryptoContext object that is used for authentication/communication
with the API
● cipherListOfList -- 2D list of ciphertext integers
A two dimensional list of ciphertext integers
● indexData -- None or int or 2D list of index integers
A two dimensional list of index integers (if passed an int this 2D list is procedurally
generated)
● fromPlain -- None or True
Indicates if the list needs to be encrypted
● seedString -- None or String
An optional seed from which to generate the one time pad keys
● keyRange -- None or int
The max value to use when generating one time pad keys
● permLevel -- string
This specifies the level of permissions granted to a newly encrypted list
```
## Methods

```
● pad ( int )
Pads each entry in the string by the specified amount
● vert_merge ( otherNCL )
This method accepts another NormCipherList and performs a vertical merge
● ngram_hashes ( n-int )
Accepts an integer less than the length of the strings in the list and returns a list of our ngram
hash values of the specified length
● ngram_distance_matrix ( n-int )
Accepts an integer less than the length of the strings in the list and returns a matrix of
approximate ngram distances between words in the list
● list_of_ciphertext ( )
Returns a ciphertext representation of the encrypted data
● search ( queryString )
Accepts either a plaintext string or a NormCipherString and returns indices of matches
contained in the list
● levenshtein ()
Accepts no arguments and returns a matrix of the Levenshtein distance between words in
the list
● custom_equality ( func )
Accepts a function as an argument. This function is intended to be a distance formula written
in regular python. This function is applied to the list. (example shown below)
● decrypt ()
Accepts no arguments and returns the decrypted list. Will raise an error if you lack the
permissions for this operation
```
## Attributes

```
● colMaxChars
Length of strings in this column
● cipherListOfList
2D list of ciphertext integers
● indicesListOfList
2D list of index integers
```
## Supported Operations

```
● len( )
● [ i ] (indexing)
● [ i : j ] (slicing)
● for encryptedWord in NormCipherList (iteration)
```

# NormCipherString

**class** NormCipherString( **myContext, cipherList, indexData=
False,permLevel=’standard’,keyRange=2000** )

This class mimics a plaintext string.

## Parameters

```
● myContext -- CryptoContext
This argument accepts a CryptoContext object that is used for authentication/communication
with the API
● cipherList -- list of ciphertext integers or str
A one dimensional list of ciphertext integers or if given a string it will encrypt the string as a
list of ciphertext integers
● indexData -- None or int or list of index integers
A one dimensional list of index integers
● keyRange -- None or int
The max value to use when generating one time pad keys
● permLevel -- string
This specifies the level of permissions granted to a newly encrypted frame
```
## Methods

```
● ciphertext ( )
This method accepts no arguments and returns a string of printable ciphertext
● decrypt ()
Accepts no arguments and returns the decrypted string. Will raise an error if you lack the
permissions for this operation
```
## Attributes

```
● length
Length of string
● cipherList
List of ciphertext integers
● indicesList
List of index integers
● pairsList
List of ciphertext integers with their corresponding index integers in tuples
```
## Supported Operations

```
● len( )
● str( )
```

# NormCipherQuant

**class** NormCipherQuant( **myContext, cipherList,
indexData=False,fromPlain=False,keyRange=32766,floatData=False,permLevel='standard'** )

This class mimics a list object with some additional methods and features.

## Parameters

```
● myContext -- CryptoContext
This argument accepts a CryptoContext object that is used for authentication/communication
with the API
● cipherList -- A list of ciphertext integers
A two dimensional list of ciphertext integers
● indexData -- None or int or list of index integers
A two dimensional list of index integers (if passed an int this 2D list is procedurally
generated)
● fromPlain -- None or True
Indicates if the list needs to be encrypted
● keyRange -- None or int
The max value to use when generating one time pad keys
● floatData -- None or True
Indicates whether the encrypted data should be treated as floating point values
● permLevel -- string
This specifies the level of permissions granted to a newly encrypted list
```
## Methods

```
● vert_merge (otherNCQ)
This method accepts another NormCipherList and performs a vertical merge
● mean ( )
Accepts no arguments and calculates the mean value of the column
● stdev ( )
Accepts no arguments and calculates the standard deviation of the column
● median ( )
Accepts no arguments and calculates the median of the column
● cosine_similarity ( other )
Accepts another NCQ and calculates the cosine similarity between them, treating them as
vectors
● dot_product ( other )
Accepts another NCQ and calculates the dot product between them, treating them as vectors
● magnitude ( )
Accepts no arguments and calculates the magnitude of this NCQ treating it as a vector
● ciphertext or list_of_ciphertext ( )
Accepts no arguments and returns a ciphertext representation of the data. Won't work if data
is floating point
● summation ( )
Accepts no arguments and returns a sum of of the column
● decrypt ( )
Accepts no arguments and returns the decrypted list. Will raise an error if you lack the
permissions for this operation
```
## Attributes

```
● floatData
Indicates if the data is treated as floating point numbers or integers
● cipherList
List of ciphertext integers
● indicesList
List of index integers
```
## Supported Operations

```
● len( )
● [ i ] (indexing)
● [ i : j ] (slicing)
● for encryptedNum in NormCipherQuant (iteration)
● ==, >, <
```

# NormCipherNum

**class** NormCipherNum(
**apiContext,cipher,index=False,fromPlain=False,floatData=False,keyRange =
2000,permLevel='standard'** )

This class mimics a plaintext int or float.

## Parameters

```
● apiContext -- CryptoContext
This argument accepts a CryptoContext object that is used for authentication/communication
with the API
● cipher -- int or float
A ciphertext int or float. Alternatively if fromPlain is True, this is a plaintext number to be
encrypted
● index -- None or int
An index integer
● fromPlain -- None or True
Indicates if the number needs to be encrypted
● keyRange -- None or int
The max value to use when generating one time pad keys
● floatData -- None or True
Indicates whether the encrypted data should be treated as a floating point value
● permLevel -- string
This specifies the level of permissions granted to a newly encrypted number
```
## Methods

```
● ciphertext ( )
This method accepts no arguments and returns a string of printable ciphertext. Will not work
if data is floating point
● decrypt ( )
Accepts no arguments and returns the decrypted number. Will raise an error if you lack the
permissions for this operation
```
## Attributes

```
● length
Length of string
● cipherList
List of ciphertext integers
● indicesList
List of index integers
● pairsList
List of ciphertext integers with their corresponding index integers in tuples
```
## Supported Operations

```
● str( )
● + , -, *, **
● ==, >=, <=, >, <, !=
```

# CryptoContext

**class** CryptoContext(self,headers):

This class manages authentication and connection to the API. One is needed to create any of the above data objects and serves as your digital identity while working with the encrypted data.

## Parameters
● headers -- dict
This should be a dictionary of the form:
{'Authorization': 'Token xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'}

# Permissions

{ “Polys”:[options], “Stats”:[options], "LaplaceScaleParameter":float }

When passing permissions in the permLevel argument for one of our data structures, use one of
our prebuilt levels of permissions (standard, open, or strict) or a json dictionary structured like
the one above. The LaplaceScaleParameter portion is optional and should only be set if you
wish your data to utilize differential privacy in addition to our encryption methods.

## Polynomial permissions

These permissions relate to the use of the polynomial endpoint. Here there are two separate
ways to allow users to calculate specific polynomials on the encrypted data you have shared
with them.

```
● Explicit strings - This explicitly allows certainpolynomials. For example, we can
explicitly allow the two given polynomials by giving the “Polys” portion of the permission object the list [‘X ** 2 + 1’, ‘X ** 2 + Y ** 3’]. These strings should always be written in the SymPy style and must match exactly with the strings passed to the endpoint.
● Regular expressions - We allow the use of regular expressions in the “Polys” list as
well for users who wish to allow certain classes or types of polynomials. The use of
regular expressions in this list does not preclude the use of explicit strings.
● allpolys - the string ‘allpolys’ inside the “Polys” list is a shortcut to allow all polynomial
expressions from approved users. Ex: { “Polys”:[‘allpolys’] }
```
## Stats permissions

Here you can allow the following specific statistical functions to be performed on your data:

```
● Mean (use ‘mean’)
● Median (use ‘median)
● Standard deviation (use ‘stdev’)
● Comparison operations (use ‘comparison’)
● Equality (use ‘equality’)
● Sorting operations (use ‘sort’)
● All stats - a shortcut to allow all the above statistical operations (use ‘allstats’)
```

## Laplace Scale Parameter

This should be a positive integer or floating point number. It should only be set if you wish to
require differential privacy to be used with your data in addition to our encryption. The number
you pass here corresponds to the ‘b’ parameter of the [Laplace distribution](https://en.wikipedia.org/wiki/Laplace_distribution). We use noise
generated by NumPy using their Laplace generator; documentation for the exact function can be
found [here](https://numpy.org/doc/stable/reference/random/generated/numpy.random.Generator.laplace.html#numpy.random.Generator.laplace).

