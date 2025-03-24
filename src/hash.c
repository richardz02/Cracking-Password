#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>
#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define MAX_PASSWORD_CHARACTER 256
#define MAX_NUM_PASSWORD 999998
#define NUM_THREADS 4

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

int compare_hashes(char *a, char *b) {
	for(int i=0; i < 2*KEEP; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}

// Set up thread argument strucutre
typedef struct arg {
    char** passwords;
    int start_index;
    int end_index;
    struct cracked_hash* cracked_hashes;
    int num_hashes;
} thread_args_t;

// This thread function will work on a split chunk of the password file
void* thread_crack_password(void* arg) {
    thread_args_t* args = (thread_args_t *) arg;
    char hex_hash[2*KEEP+1];

    // Each thread goes through each of their workload of passwords
    for(int idx = args->start_index; idx < args->end_index; idx++) {
        char* password = args->passwords[idx];

        // Use all four hashing algorithms on password to find matches
        for (int i = 0; i < n_algs; i++) {
            unsigned char* hash = fn[i]((unsigned char *) password, strlen(password));

            // Format the entire hash up to KEEP bytes
            for (int j = 0; j < KEEP; j++) {
                sprintf(&hex_hash[2*j], "%02x", hash[j]);
            }
            hex_hash[2*KEEP] = '\0';  // Ensure null termination

            for (int j = 0; j < args->num_hashes; j++) {
                if (args->cracked_hashes[j].password != NULL) {
                    continue;
                }
                if (compare_hashes(hex_hash, args->cracked_hashes[j].hash)) {
                    pthread_mutex_lock(&lock);
                    if (args->cracked_hashes[j].password == NULL) {
                        args->cracked_hashes[j].password = strdup(password);
                        args->cracked_hashes[j].alg = algs[i];
                    }
                    pthread_mutex_unlock(&lock);
                    break;
                }
            }
        }
    }

    return NULL;
}

void crack_hashed_passwords(char *password_list, char *hashed_list, char* output) {
	FILE *fp;
	char password_buffer[MAX_PASSWORD_CHARACTER];  // passwords have at most 255 characters
	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

    // Read hashes from hashed list
	int n_hashed = 0;
	struct cracked_hash *cracked_hashes;
	fp = fopen(hashed_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%s", hex_hash) == 1)
		n_hashed++;
	rewind(fp);
	cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
	assert(cracked_hashes != NULL);
	for(int i=0; i < n_hashed; i++) {
		fscanf(fp, "%s", cracked_hashes[i].hash);
		cracked_hashes[i].password = NULL;
		cracked_hashes[i].alg = NULL;
	}
	fclose(fp);

    // Read passwords from password list
	fp = fopen(password_list, "r");
	assert(fp != NULL);

    char* passwords[MAX_NUM_PASSWORD];
    int num_passwords = 0;
	while(fscanf(fp, "%s", password_buffer) == 1) {
        passwords[num_passwords] = strdup(password_buffer);
        num_passwords++;
	}
	fclose(fp);

    // Create threads
    pthread_t th[NUM_THREADS];
    thread_args_t *arg[NUM_THREADS];
    int chunk_size = num_passwords / NUM_THREADS;
    for (int i = 0; i < NUM_THREADS; i++) {
        arg[i] = malloc(sizeof(thread_args_t));
        arg[i]->passwords = passwords;
        arg[i]->start_index = i * chunk_size;
        arg[i]->end_index = (i == NUM_THREADS - 1) ? num_passwords : (i + 1) * chunk_size;
        arg[i]->cracked_hashes = cracked_hashes;
        arg[i]->num_hashes = n_hashed;
        pthread_create(&th[i], NULL, thread_crack_password, arg[i]);
    }

    // Join threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(th[i], NULL);
    }

    // Write final results to output file
	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashed; i++) {
		if(cracked_hashes[i].password ==  NULL)
			fprintf(fp, "not found\n");
		else
			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
	}
	fclose(fp);

	// Clean up allocated resources
    for (int i = 0; i < num_passwords; i++) {
        free(passwords[i]);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        free(arg[i]);
    }
	for(int i=0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	free(cracked_hashes);
}
