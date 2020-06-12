# Analysis-of-cryptographic-techniques-in-a-LAN-IM-environment
A LAN messaging application is a safe, secure and effective communication tool for sending text messages and files. It does not require a fixed server to run. It has a variety of handy features such as
In this project, we have set up a simulation LAN Messaging system. 
A number of cryptography techniques are used in order to prevent transmitted data from a number of security threats. 
Out of the multiple encryption techniques available, have performed an analysis on the following 3 cryptography techniques.
1. Advanced Encryption Standard (AES) 
2. Data Encryption Standard (DES) 
3. RSA (Rivest–Shamir–Adleman) 
The factors which have been analysed are:
1. Encryption time
2. Decryption time
3. Key generation time
4. Memory utilisation for encryption and decryption
In order to run the code:
1. Create text files of size 50KB, 500KB, 1MB, 2MB and 5MB.
2. The code for each algorithm is present in the folders- AES, DES and RSA. Run the server file first in one terminal. The client file should run
in another terminal. Open another terminal to set up another client. The presence of multiple clients allows to calculate the decryption time effectively.
3. Run the python files named as aes_memory_server.py and so on in order to get a line by line analysis of the memory utilisation.
4. The time results are present in the folder time_calculations
5. The memory results are present in the folder memory_calculations
The conclusion of our analysis was:
-- If you are looking for an algorithm which is time-efficient, AES is the best.
-- If you are looking for an algorithm which is memory-efficient, DES and AES are equally good.
-- RSA is the most secure algorithm out of the 3 due to its very large key size and also due to its asymmetric nature. 
