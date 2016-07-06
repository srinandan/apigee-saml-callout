# apigee-saml-callout
This Java callout  can:
1) Encrypt SAML Assertions 
2) Decrypt SAML Assertions
3) Validates SAML Assertion attributes (Issuer, Entity, etc.)
4) Populates custom SAML attributes as Apigee variables for access in subsequent policies

## Package
```
mvn package
```

##How to use
###Decryption
The SAML Java callout will decrypt and otherwise validate the assertion digital signature. It 
is expected the out-of-the-box SAML Validation policy will be used.

####Decryption Private Key
The Java callout uses PKCS8 format to read the private key. In order to store this securely, we read the PCKS8 as 
a byte[], then Base64 encode it and store in Apigee's vault (which itself is encrypted).

There is a second proxy implemented (node.js proxy) that reads from the vault. The basePath for this proxy is:
```
https://{router-ip}/privatekeys/{keyname}
``` 
The response is text/plain

####Attributes
All the SAML attributes are available as variables "saml_{variablename}"

##Sample
The "saml-setup" folder contains a sample implementation. Although the Java callout uses maven dependecies, I have 
put a set of JAR files. I recommend these JAR files be uploaded to environment (or org) level to keep the proxy bundle  
light. I have included cURL commands for this.

###About the sample
The sample converts a SAML assertion to an OAuth token. THe assertion is sent to Edge in a URL Encoded + Based64 Encoded 
format. To be precise, this format:

Content-Type: text/plain
HTTP Body:
```
SAMLResponse={URL encoded + Base 64 encoded string}
```

