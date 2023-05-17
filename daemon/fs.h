#ifndef __WORK_TASK_FS_H_INCLUDED__
#define __WORK_TASK_FS_H_INCLUDED__

#include "buf.h"

#include <string.h>
#include <sys/types.h>

// Save ip_vector data to the file.
void fs_dump_ip_data(char* iface, ip_vec_t* vec);

// Load ip_vector data from the file.
void fs_load_ip_data(char* iface, ip_vec_t* ip_vector);

#endif //__WORK_TASK_FS_H_INCLUDED__
