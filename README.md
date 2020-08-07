# Client-Server-based-Secure-Messenger

In the phase 1 of this project, a file and message sharing messenger was implemented using the Java Security library, and both symmetric and asymmetric encryption algorithms were used.

For message and file sharing itself, the AES algorithm was used as the cryptographic algorithm, due to its lower complexity, and with a session key between each client and the server, which is either encrypted with a physical key, or with the help of RSA algorithm. This session key is updated after certain time intervals. 

