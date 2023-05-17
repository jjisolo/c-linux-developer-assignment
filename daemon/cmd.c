#include "cmd.h"
#include "net.h"

#define NET_SERVER_MESSAGE_MAXLEN 2048
#define CMD_DAEMON_DIRECTORY      "/var/lib/work-task/"

#define server_print(string) \
    snprintf(message, NET_SERVER_MESSAGE_MAXLEN, string); \
    write(socket_client, message, strlen(message))

#define server_printf(string, ...) \
    snprintf(message, NET_SERVER_MESSAGE_MAXLEN, string, __VA_ARGS__); \
    write(socket_client, message, strlen(message))

#define server_command(string) \
    strcmp(command->command, string) == 0

#define server_arg1(string) \
    strcmp(command->arg1, string) == 0

#define server_arg2(string) \
    strcmp(command->arg2, string) == 0

static const char* HELP_MESSAGE = "Packet sniffer\n"
                                  "\nCLI commands list:\n"
                                  "\tstart -- packets are sniffed from binded iface(the default one is eth0).\n"
                                  "\tstop  -- stop the packet sniffing.\n"
                                  "\tshow [ip] count show the count of IP entries from the binded iface.\n"
                                  "\tselect iface [iface] -- bind interface for sniffing.\n"
                                  "\thelp -- display this message.\n";

static char* itoa(int val, int base) {
    static char buf[32] = {0};
    int i = 30;
    for(; val && i ; --i, val /= base)
        buf[i] = "0123456789abcdef"[val % base];

    return &buf[i+1];

}

static void cmd_print_vector_data(ip_vec_t* ip_vector, char message[NET_SERVER_MESSAGE_MAXLEN], char buffer[256]) {
    for(size_t i=0; i < ip_vector->length; ++i) {
        ip_vec_data data = iv_vec_safe_get(ip_vector, i);

        if((strlen(message) + strlen(data.ip_address) + strlen(itoa(data.ip_address_num, 10))) > NET_SERVER_MESSAGE_MAXLEN)
            break;

        snprintf(buffer, 256, "[%lu] %s\t\t %lu\n", i, data.ip_address, data.ip_address_num);
        strcat(message, buffer);
    }
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


void cmd_command_callback(int socket_client, int* socket_sniff, command_t* command) {
    char message[NET_SERVER_MESSAGE_MAXLEN];

    // START COMMAND
    if(server_command("start")) {
        // If there is more than one argument is provided.
        if(command->arg2 || command->arg1) {
            server_print("Error: invalid argument(s). The correct usage of the command: > start");
        }
        else {
          server_printf("start sniffing packet on iface %s", net_get_binded_iface());
          net_start_sniffing();
        }
    }

    // STOP COMMAND
    else if(server_command("stop")) {
        server_printf("stopping sniffing packet on iface %s", net_get_binded_iface());
        net_stop_sniffing();
    }

    // STOP COMMAND
    else if(server_command("select")) {

        if(!command->arg1) {
            server_print("Usage: select iface [iface]");
        }
        else {

            if(server_arg1("iface")) {

                if(command->arg2) {
                    // Create the new socket and try to bind it to the new inteface.
                    int socket_sniff2 = net_create_sniffing_socket();

                    if(net_bind_socket_to_iface(socket_sniff2, command->arg2) == 0) {
                        // If the binding is successfull set socket_sniff2 is now dominant.
                        close(*socket_sniff);
                        *socket_sniff = socket_sniff2;
                        net_bind_sniffer_socket(*socket_sniff);

                        server_printf("iface %s is binded to the sniffer", command->arg2);
                    } else {
                        server_printf("Error: cannot bind iface %s", command->arg2);
                    }

                } else {
                    server_print("Error: no iface is specified to the sniffer(consider typing `help` command)");
                }
            } else {
                server_print("Usage: select iface [iface]");
            }
        }
    }

    // SHOW COMMAND
    else if(strcmp(command->command, "show") == 0) {

        if(!command->arg1) {
            server_print("Usage: show [ip] count");
        }
        else {

            if(!command->arg2) {
                server_print("Usage: show [ip] count");
            }

            else if(!(server_arg2("count"))) {
                server_print("Error: invalid argument on position 3. Usage: show [ip] count");
            }

            else {
                long ip_number = net_get_ip_count(command->arg1);
                if(ip_number == -1) {
                    server_printf("No entries for IP %s were found", command->arg1);
                }

                else {
                    server_printf("IP occurences count for %s: %ld", command->arg1, ip_number);
                }
            }
        }
    }

    // STAT COMMAND
    else if(server_command("stat")) {

        // E.G. stat [iface] []
        if(!command->arg2) {
            // List all directories in the program folder.
            DIR *directory_handle = opendir(CMD_DAEMON_DIRECTORY);

            // Clear the buffer.
            char buffer[256];
            memset(message, '\0', NET_SERVER_MESSAGE_MAXLEN*sizeof(char));
            snprintf(buffer, 256, "%s:\n", "Cached ip data:");

            if(directory_handle) {
                struct dirent *directory;

                // For each directory in the folder, print the file contents.
                while((directory = readdir(directory_handle)) != NULL) {
                    ip_vec_t ip_vector = {0};

                    // Parse only files.
                    if(directory->d_type == DT_DIR)
                        continue;

                    // If the iface is currently binded, do not load it from the file,
                    // because it is either do not exist, or the up to date data is
                    // stored in the memory
                    if(strcmp(directory->d_name, net_get_binded_iface()) != 0)
                        fs_load_ip_data(directory->d_name, &ip_vector);
                    else
                        continue;

                    // Prepare the message buffer
                    char buffer[256];

                    // Print the current directory name
                    snprintf(buffer, 256, "%s:\n", directory->d_name);
                    strcat  (message, buffer);

                    // If the data dump loaded(it can be not if the cache file size is 0)
                    if(ip_vector.length > 0)
                        // For each vector element append the ip address in its entry count
                        // to the server message if the [iface] parameter does not specified.
                        // If it is, print only the requested iface here or below.
                        if(!command->arg1 || strcmp(directory->d_name, command->arg1) == 0)
                            cmd_print_vector_data(&ip_vector, message, buffer);

                    // Do not free the net binded vector.
                    if(strcmp(directory->d_name, net_get_binded_iface()) != 0)
                        iv_vec_release(&ip_vector);

                }

                closedir(directory_handle);
            }

            // Display the binded vec contents if there are was not cached.
            if(!command->arg1 || strcmp(command->arg1, net_get_binded_iface()) == 0) {
                char* binded_iface = net_get_binded_iface();

                char buffer[256];
                snprintf(buffer, 256, "%s:\n", binded_iface);
                strcat  (message, buffer);

                ip_vec_t ip_vector = net_get_binded_ip_vector();
                fs_dump_ip_data(binded_iface, &ip_vector);         // Dump the current sniff data(append to the previous if exists).

                iv_vec_create        (&ip_vector);                 // To occasionally not to delete the binded vector data.
                fs_load_ip_data      (binded_iface, &ip_vector);   // Load the sniff data plus the previously cached.
                cmd_print_vector_data(&ip_vector, message, buffer);
                iv_vec_release       (&ip_vector);
            }

            write(socket_client, message, strlen(message));
        }

        else {
            server_print("Usage: stat [iface]");
        }
    }

    else if(server_command("help")) {
        server_print(HELP_MESSAGE);
    }

    else {
        server_print("Error: invalid command");
    }
}
