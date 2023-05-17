
#include "fs.h"

#define FS_HOME_FOLDER      "/var/lib/work-task/"
#define FS_FILE_ERR_NOBYTES "the file size is "

static char* fs_costruct_filename(char *iface) {
    char *filename = (char *)malloc(256);
    strcpy(filename, FS_HOME_FOLDER);
    strcat(filename, iface);

    return filename;
}

void fs_dump_ip_data(char* iface, ip_vec_t* ip_vector) {
    char* file_name    = fs_costruct_filename(iface);
    FILE* file_pointer = fopen(file_name, "w+");

    // For each data struct in the vector, write it in the file.
    syslog(LOG_DEBUG, "Dumping ip data to the %s", file_name);
    for(size_t i = 0; i < ip_vector->length; ++i) {
        ip_vec_data vec_data = iv_vec_safe_get(ip_vector, i);
        fprintf(file_pointer, "%s %lu\n", vec_data.ip_address, vec_data.ip_address_num);
    }

    fclose(file_pointer);
    free  (file_name);
}

void fs_load_ip_data(char* iface, ip_vec_t* ip_vector) {
    if(!iface || !ip_vector)
        return;

    // If we passed the previously-initialized vector, recreate it.
    if(ip_vector->_data)
        iv_vec_release(ip_vector);
    iv_vec_create (ip_vector);

    // Try open the file. If opening fails, return the
    // blank vector.
    char* file_name      = fs_costruct_filename(iface);
    FILE* file_pointer   = fopen(file_name, "r");

    if(file_pointer == NULL) {
        syslog(LOG_DEBUG, "Iface %s cache is not found", iface);
        free  (file_name);
        return;
    }

    // Read the peviouslt cached files.
    char*   line   = NULL;
    size_t  length = 0;

    // Do not read the zero-sized files.
    fseek(file_pointer, 0, SEEK_END);
    long file_size = ftell(file_pointer);
    fseek(file_pointer, 0, SEEK_SET);

    syslog(LOG_DEBUG, "Loading ip entries cache from %s", file_name);
    if(file_size != 0) {
        while(true) {
            // Read all file contents.
            if(getline(&line, &length, file_pointer) == -1)
              break;

            char* ip_address     = strtok(line, " ");
            char* ip_address_num = strtok(NULL, " ");
            if((ip_address == NULL) || (ip_address_num == NULL))
                continue;

            char* ip_address_dynamic = (char *)malloc(strlen(ip_address)+1);
            if(!ip_address_dynamic) {
                syslog(LOG_EMERG, "Unable to allocate space for the ip address value!");
                continue;
            }

            strcpy     (ip_address_dynamic, ip_address);
            iv_vec_push(ip_vector,          ip_address_dynamic);
            ip_vector->_data[ip_vector->length-1].ip_address_num = atoi(ip_address_num);
        }
    }

    fclose(file_pointer);
    free  (file_name);

    if(line)
      free(line);
}
