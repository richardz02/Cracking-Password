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

# Progress Update - 1
So I tried the approach of spawning four threads per password for each hash algorithm that we have to check if it matches with any hashes from the hashed list. It turns out the program was running even longer about (14 ~ 16 seconds)

Here are some reasons why after doing some research:
- Since we have 999,999 passwords in the password file, this means my program was spawning almost 4 million threads, the CPU is probably spending more time creating and destorying threads than actually cracking passwords
- Since threads are constantly switching (context switch), having almost 4 million threads means large overhead in context switching
- Too much mutex locking, threads spend time waiting for locks

A better approach which I found is:
- Use a fixed thread pool (fixed number of threads)
- Each thread process multiple passwords instead of just one
- Assign passwords to threads dynamically
  - instead of one thread per hash function per password, create a share work queue
  - Each thread pulls a password from the queue, tries with all four hash algorithms, and compares
  - Only lock cracked_hashes when a match is found

# Progress Update - 2
For the second attempt at this assignment, I created a simple queue data structure, which we would fill in the password as we read the password file. This queue will act as a shared queue amongst the threads, and each thread will fetch a password at a time from the shared queue, compute hashes, and check for matches. This approach was able to achieve 2x speed up after testing. 

# Progress Update - 3
There are still a few issues with the previous approach that was slowing down the program: 
- The frequent synchronization (use of locks) might be slowing down the program, since if multiple threads are trying to access the queue, then they would spend time waiting for one thread to finish fetching the password before another thread can proceed

New approach:
- Divide the password file evenly amongst the threads
- Threads will independently process the chunk of password assigned to them

Why is this approach optimal?
- Reduced synchronization, reduce overhead from constantly locking and unlocking the shared queue when accessing it
- Threads don't have to wait for another thread to finish fetching from the shared queue
