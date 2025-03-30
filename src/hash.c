#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>
#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define MAX_PASSWORD_CHARACTER 256
#define NUM_THREADS 8
#define HASHMAP_SIZE 4096

/***********************************
**     Hash Map Implementation
 ***********************************/
// Node structure for hash map entries
typedef struct hash_node {
    char* key;           // The hash string (key)
    int value;           // The index into cracked_hashes array (value)
    struct hash_node* next;  // Pointer to next node (for collision handling)
} hash_node_t;

// Hash map structure
typedef struct {
    hash_node_t** buckets;  // Array of pointers to nodes
    int size;               // Number of buckets
    int count;              // Number of entries
} hash_map_t;

// Create a new hash map with specified size
hash_map_t* hash_map_create(int size) {
    hash_map_t* map = (hash_map_t*)malloc(sizeof(hash_map_t));
    if (!map) return NULL;

    map->size = size;
    map->count = 0;
    map->buckets = (hash_node_t**)calloc(size, sizeof(hash_node_t*));

    if (!map->buckets) {
        free(map);
        return NULL;
    }

    return map;
}

// Hash function for strings (using djb2 algorithm)
unsigned int hash_string(const char* str, int size) {
    unsigned int hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash % size;
}

// Insert a key-value pair into the hash map
bool hash_map_insert(hash_map_t* map, const char* key, int value) {
    if (!map) return false;

    unsigned int index = hash_string(key, map->size);

    // Create new node
    hash_node_t* new_node = (hash_node_t*)malloc(sizeof(hash_node_t));
    if (!new_node) return false;

    new_node->key = strdup(key);
    if (!new_node->key) {
        free(new_node);
        return false;
    }

    new_node->value = value;

    // Insert at the beginning of the linked list
    new_node->next = map->buckets[index];
    map->buckets[index] = new_node;
    map->count++;

    return true;
}

// Find a value by key
bool hash_map_find(hash_map_t* map, const char* key, int* result) {
    if (!map) return false;

    unsigned int index = hash_string(key, map->size);
    hash_node_t* current = map->buckets[index];

    while (current) {
        if (strcmp(current->key, key) == 0) {
            *result = current->value;
            return true;
        }
        current = current->next;
    }

    return false;
}

// Free all memory used by the hash map
void hash_map_destroy(hash_map_t* map) {
    if (!map) return;

    for (int i = 0; i < map->size; i++) {
        hash_node_t* current = map->buckets[i];
        while (current) {
            hash_node_t* temp = current;
            current = current->next;
            free(temp->key);
            free(temp);
        }
    }

    free(map->buckets);
    free(map);
}


/*****************************************
 *   Cracking Password Implementation    *
 *****************************************/
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t counter_lock = PTHREAD_MUTEX_INITIALIZER;

volatile int cracked_count = 0;
volatile bool stop_processing = false;

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
    hash_map_t* hash_map;
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

            // Look up the hash in our hash map (O(1) operation)
            int hash_index;
            if (hash_map_find(args->hash_map, hex_hash, &hash_index)) {
                pthread_mutex_lock(&lock);
                if (args->cracked_hashes[hash_index].password == NULL) {
                    args->cracked_hashes[hash_index].password = strdup(password);
                    args->cracked_hashes[hash_index].alg = algs[i];

                    // Update cracked count and check if we're done
                    pthread_mutex_lock(&counter_lock);
                    cracked_count++;
                    if (cracked_count >= args->num_hashes) {
                        stop_processing = true;
                    }
                    pthread_mutex_unlock(&counter_lock);
                }
                pthread_mutex_unlock(&lock);
            }
            free(hash);
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

    // Create hashmap for fast lookups
    hash_map_t* hash_map = hash_map_create(HASHMAP_SIZE);
    assert(hash_map != NULL);

    for (int i = 0; i < n_hashed; i++) {
        fscanf(fp, "%s", cracked_hashes[i].hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;

        // Insert each hash value into the hash map with its index
        hash_map_insert(hash_map, cracked_hashes[i].hash, i);
    }
	fclose(fp);

    // Read passwords from password list
	fp = fopen(password_list, "r");
	assert(fp != NULL);

    char** passwords = NULL;
    int num_passwords = 0;
    int capacity = 0;
	while(fscanf(fp, "%s", password_buffer) == 1) {
        if (num_passwords >= capacity) {
            capacity = capacity == 0 ? 1024 : capacity * 2; // Initial size 1024, then double as needed
            passwords = (char **)realloc(passwords, capacity * sizeof(char *));
            assert(passwords != NULL);
        }
        passwords[num_passwords] = strdup(password_buffer);
        num_passwords++;
	}
	fclose(fp);

    // Reset global variables
    cracked_count = 0;
    stop_processing = false;

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
        arg[i]->hash_map = hash_map;
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

    // Free memory allocated for hash map
    hash_map_destroy(hash_map);
}
