Before you read too much below, you might consider having a look at 
- these [streamlined setup instructions](https://github.com/capnion/ghostpii_client/blob/main/SETUP.md), 
- our [Slack workspace](https://join.slack.com/t/ghostpii/shared_invite/zt-1bkub2k10-aPrBYOowvyxwJehcdePmAw), or
- our library of tutorials (as .ipynb files in this [Github repo](https://github.com/capnion/ghostpii_demos) or as [interactive Jupyter notebooks via Binder](https://mybinder.org/v2/gh/capnion/ghostpii_demos/main)).

While the tutorials are presented in Jupyter notebooks, you can use Ghost PII anywhere you use Python.  Ghost PII is maintained by Capnion, Inc. and you can learn more about our company [here](https://www.capnion.com).  If you are interested in regular updates on Ghost PII, new tutorials, or discussions of business value and application then you should check out Alexander Mueller on [LinkedIn](https://www.linkedin.com/in/alexander-c-mueller-phd-0272a6108/), [YouTube](https://www.youtube.com/channel/UCBoNwoccEVg0S5IsYPNHtBg), or the Capnion [blog](https://www.capnion.com/blog).

# What is Ghost PII?

Ghost PII is a technology for... 
- encrypting data, 
- enabling others to extract insights from that encrypted data without decrypting, and 
- regulating what insights are available to whom.  

Here “insights” really means anything you might compute from the data to drive a decision, and regulating who can extract what insights will let you share more data to accomplish more while giving you more control over the risks that come with sharing.  For example, if you are making a website for a bar, you might obtain a birth date from a user when you are really only interested in whether that birth date was 21 or more years ago (in the United States anyway).  You can use Ghost PII to keep that birth date encrypted all through your pipeline, yet still compute a True or False answer to the question “Is this birthday more than 21 years ago?” at the appropriate place in your application logic.  This is a purposely simple example and Ghost PII supports arbitrary computations, machine learning and statistics, and can provide the control described (and also auditability) even when you have passed the encrypted data to others.

From an architectural perspective, Ghost PII is a Python module that interacts with a specialized keyhosting API via the web or other network.  This repo contains the code of that Python module, a number of tutorials in the form of Jupyter notebooks, as well as instructions for accessing the keyhosting API .  Ghost PII is designed to mesh seamlessly with the broader open source Python data ecosystem and to be easily accessible to Python familiar engineers and data scientists without need of additional training.  In many cases, the encrypted data objects in Ghost PII can be handled with exactly the same code you would use to handle the analogous string or integer object in base Python with analogous results.

Specifically, Ghost PII provides encryption functionality, the (unique and novel) ability to compute some things but not others from that specially encrypted data, and a flexible permissions and audit system both to designate who can compute what as well as if and when they did it.

<p align="center">
  <img src="https://github.com/capnion/ghostpii_client/blob/main/github.png">
</p>

# How does Ghost PII work?

The technologically novel part of the answer is that Ghost PII employs a variety of emerging privacy-enhancing technologies (sometimes abbreviated as PETs) including… 
- homomorphic encryption,
- differential privacy, and
- secure multi-party computation.

However, Ghost PII does not require the user to interact directly with these technologies nor does it require significant knowledge of their workings.  Ghost PII’s client-side module provides special data types and methods for handling specially encrypted data.  When these methods are called, the module interprets it in order to…
- perform special mathematical computations on the encrypted data, and
- download a special “answer key” from the remote key hosting API (when appropriate).

This answer key is relatively unique to Ghost PII and allows the decryption of the outcome of the computation in question, yet it does not allow the original data to be decrypted or otherwise leak additional information about it. 

The short story, though, is that you interact with familiar objects like lists and data frames, call modeling routines, etc. and the module automatically and invisibly talks to a remote service to provide you with answers where you are permitted them and explicit denials where you are not.

Finally, but possibly most importantly for some stakeholders, the role played by the remote service allows the data owner to track how it is being used, even if they have already handed it off to someone else who is working with it on another system beyond the control and visibility of the data owner.

# Who created Ghost PII?  And about the keyhosting API

Ghost PII is maintained by Capnion, Inc.  We maintain an instance of the keyhosting API, intended for curious researchers and test-drivers, open to all potential users at no charge.  You can find it at www.ghostpii.com along with the previously mentioned audit functionality and an interface for obtaining, modifying, and retrieving the user identity tokens you can see in our tutorial examples.  The future is always uncertain but we intend to maintain this free test service indefinitely.  We make no specific guarantees regarding this free-access instance of the API, and please be forgiving of performance variance in particular - as we do no gatekeeping, we have limited ability to address impacts of scale and user behavior on performance.  

If you are interested in a more thorough test-drive, and especially if performance is important, please contact [acmueller@capnion.com](acmueller@capnion.com).   Among other options, it is exceptionally easy to stand up an instance of the API in your favorite cloud environment, doing so often significantly improves performance for limiting network latency issues, and this is often the best option for users at large organizations for these and other reasons. 

And we would love your feedback in general!
