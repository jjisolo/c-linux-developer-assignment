
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

typedef struct {
  char*         ip_address;       // Actual IP address.
  unsigned long ip_address_num;   // Number of the same IP addresses
  unsigned long _ip_address_hash; // Used for the binary search.
} ip_vec_data;

typedef struct {
  size_t       capacity; // Capacity(in bytes) of the buffer.
  size_t       length;   // Its length.
  bool         _sorted;  // Should be set to false after every push operation
  ip_vec_data* _data;    // The actual data that is stored in vector.
} ip_vec_t;

// Allocate the space for the buffer.
void iv_vec_create(ip_vec_t* vec);

// Grow the buffer data segment.
void iv_vec_enhance(ip_vec_t* vec);

// Push data to the buffer.
void iv_vec_push(ip_vec_t* vec, char* ip_address);

// Set the data pointer by index(range-checked).
void iv_vec_safe_set(ip_vec_t* vec, size_t index, char *ip_address);

// Get the data pointer by index(range-checked).
ip_vec_data iv_vec_safe_get(ip_vec_t* vec, size_t index);

// Deallocate the memory that buffer occupies.
void iv_vec_release(ip_vec_t* vec);

// Perform binary search
int iv_vec_find_dev(ip_vec_t* vec, unsigned int hash, int low, int high);

int iv_vec_find(ip_vec_t* vec, char* ip);

// Perform Merge sort
void iv_merge_sort(ip_vec_t* vec, int low, int high);
