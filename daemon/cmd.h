#ifndef __WORK_TASK_CMD_H_INCLUDED__
#define __WORK_TASK_CMD_H_INCLUDED__

#include <stdlib.h>
#include <dirent.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct {
    char* command;
    char* arg1;
    char* arg2;
} command_t;

void cmd_display_welcome_message(int socket);

void cmd_parse_command_message(char *buffer, command_t* command);

void cmd_command_callback(int socket_client, int* socket_sniff, command_t* command);

#endif // __WORK_TASK_CMD_H_INCLUDED__
