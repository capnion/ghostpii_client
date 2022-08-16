Ghost PII is presently available via both of the common Python package managers pip and conda .  The commands required (the first for pip, the second for conda) are below.

pip install ghostPii

conda install -c capnion ghostpii

You will need a token (really just a long string long string of special text) to interact with the key hosting API.  You can see the use of these tokens in opening an API connection at the top of each of our many [tutorial notebooks](https://github.com/capnion/ghostpii_demos).  You can obtain this token by visiting [www.ghostpii.com](https://www.ghostpii.com), clicking "Create New User", and entering your email along with a chosen username.  The token will then be emailed to the given address.  

The portal mentioned also allows you to perform several other important tasks including 
- recovering your token if you have lost it,
- creating organizations and subordinate users inside them,
- setting permissions for how data you encrypt will be used,
- auditing how other users use encrypted data you have shared with them.




