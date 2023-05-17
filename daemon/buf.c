#include "buf.h"

// djb2 hashing from http://www.cse.yorku.ca/~oz/hash.html
static unsigned iv_hash_string(char *string) {
  unsigned long hash = 5381;
  int           chr;

  while((chr = *string++)) {
    hash = ((hash << 5) + hash) + chr;
  }

  return hash % 246822;
}

static void iv_merge(ip_vec_t* vec, int low, int middle, int high) {
  ip_vec_data temp[high - low + 1];

  size_t position      = 0;
  size_t position_low  = low;
  size_t position_high = middle + 1;

  while(position_low <= (size_t)middle && position_high <= (size_t)high) {
      if(vec->_data[position_low]._ip_address_hash < vec->_data[position_high]._ip_address_hash) {
        temp[position++] = vec->_data[position_low++];
      }
      else {
        temp[position++] = vec->_data[position_high++];
      }
  }

  while(position_low  <= (size_t)middle) {
    temp[position++] = vec->_data[position_low++];
  }
  while(position_high <= (size_t)high) {
    temp[position++] = vec->_data[position_high++];
  }

  for(size_t i = 0; i < position; ++i) {
    vec->_data[i + low] = temp[i];
  }
}

ip_vec_t* iv_vec_create(ip_vec_t* vec) {
  vec->capacity  = 2;
  vec->length    = 0;
  vec->_sorted   = false;
  vec->_data     = (ip_vec_data *)malloc(sizeof(ip_vec_data) * vec->capacity);

  return vec;
}

void iv_vec_enhance(ip_vec_t* vec) {
  // Use ammortized constant-time buffer grow.
  ip_vec_data* data = realloc(vec->_data, sizeof(ip_vec_data) * vec->capacity*2);

  if(data) {
    vec->capacity = vec->capacity*2;
    vec->_data    = data;
  }
  else {
    syslog(LOG_DEBUG, "Error: reallocation of an ip_vec failed.");
  }
}

void iv_vec_push(ip_vec_t* vec, char* ip_address) {
  // Grow the vector if the maximum capacity has reached.
  if(vec->capacity == vec->length) {
    iv_vec_enhance(vec);
  }

  // If the IP that is provided already exists in the vec,
  // increment the IP occurence counter by 1.
  if(vec->length > 1) {
      // This operation performed using binary search algorithm.
      const int same_element_index = iv_vec_find_dev(vec, iv_hash_string(ip_address), 0, vec->length-1);

      if(same_element_index != -1) {
          // Increment the ip counter.
          vec->_data[same_element_index].ip_address_num += 1;

          // The element data is not used, so need to be released.
          free(ip_address);

          return;
      }
  }

  // Otherwise create new ip_vec_data cell with the new ip
  // address, since there is the only one element here,
  // ip_address_num is set to 1.
  ip_vec_data ip_data;
  ip_data.ip_address_num   = 1;
  ip_data.ip_address       = ip_address;
  ip_data._ip_address_hash = iv_hash_string(ip_address);

  vec->_data[vec->length++] = ip_data;
  vec->_sorted              = false;
}

void iv_vec_safe_set(ip_vec_t* vec, size_t index, char* ip_address) {
  assert(index <= vec->length);

  vec->_data[index].ip_address       = ip_address;
  vec->_data[index]._ip_address_hash = iv_hash_string(ip_address);
}

ip_vec_data iv_vec_safe_get(ip_vec_t* vec, size_t index) {
  assert(index <= vec->length);

  return vec->_data[index];
}

void iv_vec_release(ip_vec_t* vec) {
  if(!vec || !vec->_data)
      return;

  for(size_t i = 0; i < vec->length; ++i)
    free(vec->_data[i].ip_address);
  free(vec->_data);

  vec->capacity  = 2;
  vec->length    = 0;
  vec->_sorted   = false;
}

void iv_merge_sort(ip_vec_t* vec, int low, int high) {
  if(low < high) {
    // Find the array mediana
    int middle = low + ((high - low) >> 1);

    // Split the array by on sides, and sort them
    // sepparatly.
    iv_merge_sort(vec, low,      middle);
    iv_merge_sort(vec, middle+1, high);

    // Merge the two sorted arrays.
    iv_merge(vec, low, middle, high);
  }
}

int iv_vec_find_dev(ip_vec_t* vec, unsigned int hash, int low, int high) {
  // The binary search applies only to the sorted arrays,
  // due to the mediana calculations.
  if(!vec->_sorted) {
    iv_merge_sort(vec, 0, vec->length-1);
    vec->_sorted = true;
  }

  if(low <= high) {
    // Find the array mediana.
    int middle = low + ((high - low) >> 1);

    // If the target hash is the mediana.
    if(vec->_data[middle]._ip_address_hash == hash) {
	  return middle;
	}

    // The hash is on the lower side.
    if(vec->_data[middle]._ip_address_hash > hash) {
      return iv_vec_find_dev(vec, hash, low, middle-1);
	}
    // The hash os on the upper side.
    else {
      return iv_vec_find_dev(vec, hash, middle+1, high);
    }
  }

  return -1;
}

int iv_vec_find(ip_vec_t* vec, char* ip) {
    return iv_vec_find_dev(vec, iv_hash_string(ip), 0, vec->length);
}

