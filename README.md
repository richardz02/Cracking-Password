# OS-Project-Cracking-Password

So we need to modify the hash.c file to make the process of cracking passwords faster.
Looking at the crack_hashed_passwords function, I noticed the following things:
1. Program loads and reads from the hashed list and password list files sequentially
   - It also fills in the array of cracked_hash structure as it reads from the hashed list
2. When comparing the passwords, the program tries all four possible hash functions for one password
   - If one of the possible ways of hashing a password matches a hashed password, then it completes the cracked_hashes structure by setting the password and the type of hashing function used
3. After the search is finished, write results to an output file

Where I think threads could be used in this program to speed up the process:
- Instead of checking all four possible hash functions for each password in a single loop, we could create four threads. Each thread is responsible for checking the password with a specific hash function.
- Could maybe use two threads at the beginning for reading the files, doesn't need to be done sequentially
