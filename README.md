# Client-Server-based-Secure-Messenger

### Phase 1:
A file and message sharing messenger was implemented using the Java Security library, and both symmetric and asymmetric encryption algorithms were used.
For the message and file sharing itself, the AES algorithm was used as the cryptographic algorithm, due to its lower complexity. 
A session key is set between each client and the server, which is either encrypted with a physical key, or with the help of RSA algorithm. This session key is updated by the server, after certain time intervals. 
message authentication code (MAC) has also been implemented to confirm that the message has not been changed.

### Phase 2:
A two way PKC authentication has been implemented and digital signatures have been used.
