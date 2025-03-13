#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept

// TODO: Implement a simple queue data structure
// This queue will contain passwords from the password file
/*
*************************************************************
**                 Queue Implementation
*************************************************************
*/
typedef struct node_t {
    char password[256];
    struct node_t* next;
} Node;

typedef struct queue_t {
    Node *front, *rear;
} Queue;

// Initialize a new node
Node* create_node(char password[256]) {
    Node* new_node = malloc(sizeof(Node));
    strcpy(new_node->password, password);
    new_node->next = NULL;
    return new_node;
}

// Initialize a new queue
Queue* create_queue() {
    Queue* q = malloc(sizeof(Queue));
    q->front = q->rear = NULL;
    return q;
}

// Checks if the queue is empty
bool is_empty(Queue* q) {
    // If both the front and rear pointer point to NULL, the queue is empty
    if (q->front == NULL) {
        return true;
    }

    return false;
}

// Insert element to the end of queue
void enqueue(Queue* q, char password[256]) {
    Node* new_node = create_node(password);

    // If the queue is empty, initialize the head of the queue and tail of the queue to the new node
    if (is_empty(q)) {
        q->front = q->rear = new_node;
        return;
    }

    // Otherwise, add the new node at the end of the queue
    q->rear->next = new_node;
    q->rear = new_node;
}

// Pop the front of the queue
void dequeue(Queue* q) {
    // If the queue is empty, simply return
    if (is_empty(q)) return;

    Node* temp = q->front;
    q->front = q->front->next;

    // If the front of queue is empty, queue is empty, set rear of queue to NULL
    if (q->front == NULL) {
        q->rear = NULL;
    }

    // Free allocated resource
    free(temp);
}

char* get_front(Queue* q) {
    // Check to see if the queue is empty
    if (is_empty(q)) {
        printf("Queue is empty.\n");
        return NULL;
    }

    return q->front->password;
}

char* get_rear(Queue* q) {
    // Check to see if the queue is empty
    if (is_empty(q)) {
        printf("Queue is empty.\n");
        return NULL;
    }

    return q->rear->password;
}

// Debug function, to check what's in the queue
void print_queue(Queue* q) {
    Node* current = q->front;

    int count = 0;
    while (current != NULL) {
        current = current->next;
        count++;
    }
    printf("Processed %d passwords.\n", count);
}

/************************************************************/

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

pthread_mutex_t queue_lock; // mutex

typedef struct arg {
    Queue* shared_queue;
    struct cracked_hash* cracked_hashes;
    int num_hashes;
} thread_args_t;

// This will be the function to run on threads
// Each thread will pull passwords from the queue and work on cracking them
void* worker_crack_password(void* arg) {
    thread_args_t* args = (thread_args_t *) arg;
    char hex_hash[2*KEEP+1];

    while (1) {
        pthread_mutex_lock(&queue_lock);

        if (is_empty(args->shared_queue)) {
            pthread_mutex_unlock(&queue_lock);
            break;
        }

        // Fetch password from queue
        char* password = get_front(args->shared_queue);
        char password_copy[256];
        strcpy(password_copy, password);  // Create a local copy
        dequeue(args->shared_queue);

        pthread_mutex_unlock(&queue_lock);

        for (int i = 0; i < n_algs; i++) {
            unsigned char* hash = fn[i]((unsigned char *) password_copy, strlen(password_copy));

            // Format the entire hash up to KEEP bytes
            for (int j = 0; j < KEEP; j++) {
                sprintf(&hex_hash[2*j], "%02x", hash[j]);
            }
            hex_hash[2*KEEP] = '\0';  // Ensure null termination

            for (int j = 0; j < args->num_hashes; j++) {
                if (args->cracked_hashes[j].password != NULL)
                    continue;
                if (compare_hashes(hex_hash, args->cracked_hashes[j].hash)) {
                    args->cracked_hashes[j].password = strdup(password_copy);
                    args->cracked_hashes[j].alg = algs[i];
                    break;
                }
            }
        }
    }
    return NULL;
}
// Need a condition variable to signal the thread to do something when the queue is not empty
// Need a lock on the shared queue since it is a shared resource
void crack_hashed_passwords(char *password_list, char *hashed_list, char* output) {
	FILE *fp;
	char password[256];  // passwords have at most 255 characters
	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

    // Initialize the shared queue and the lock
    Queue* shared_queue = create_queue();
    pthread_mutex_init(&queue_lock, NULL);

	// load hashed passwords
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

    // Load passwords from the password file, and add them to shared queue
	fp = fopen(password_list, "r");
	assert(fp != NULL);

	while(fscanf(fp, "%s", password) == 1) {
        enqueue(shared_queue, password);
	}
	fclose(fp);

    // NOTE: Password added successfully
    char* front = get_front(shared_queue);

    // TODO: Now that assume all passwords have been added to the shared queue, need threads to start working
    // FIXME: Currently this functionality is not working
    // Set up thread argument structure
    thread_args_t* arg = malloc(sizeof(thread_args_t));
    arg->cracked_hashes = cracked_hashes;
    arg->num_hashes = n_hashed;
    arg->shared_queue = shared_queue;

    // Create threads
    pthread_t th[4];
    for (int i = 0; i < 4; i++) {
        if(pthread_create(&th[i], NULL, &worker_crack_password, (void *) arg) != 0) {
            perror("Failed to create threads.\n");
        };
    }

    // Join threads
    for (int i = 0; i < 4; i++) {
        if (pthread_join(th[i], NULL) != 0) {
            perror("Failed to join threads.\n");
        }
    }

    // Destory the lock
    pthread_mutex_destroy(&queue_lock);

    // print results
	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashed; i++) {
		if(cracked_hashes[i].password ==  NULL)
			fprintf(fp, "not found\n");
		else
			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
	}
	fclose(fp);

	// release stuff
	for(int i=0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	free(cracked_hashes);
}
