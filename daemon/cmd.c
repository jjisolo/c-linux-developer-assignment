#include "cmd.h"

#define CMD_LINE_DECORATION "\n(daemon) > "

void cmd_display_prompt(int socket) {
    write(socket, CMD_LINE_DECORATION, strlen(CMD_LINE_DECORATION));
}

void cmd_display_welcome_message(int socket) {
    const char* weclome_message = "\n\n####### Welcome to the Daemon CLI interface #######\n\n";
    write(socket, weclome_message, strlen(weclome_message));
}

void cmd_parse_command_message(char *buffer, command_t* command) {
    char*  token     = strtok(buffer, " ");
    size_t token_num = 0;

    while(token != NULL) {
        switch(token_num) {
            case 0: {
                command->command = token;
            } break;

            case 1: {
                command->arg1 = token;
            } break;

            case 2: {
                command->arg2 = token;
            } break;
        };

        token_num++;
        token = strtok(NULL, " ");
    }

}

