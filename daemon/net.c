#include "net.h"

char* net_get_dest_ip(unsigned char *buffer, int size) {
  // Retrieve the IP header from this header.
  struct iphdr *ip_header = (struct iphdr *)buffer;

  // Create the struct for the inet_ntoa function
  struct sockaddr_in source;

  // And populate it with the source address of the packet
  source.sin_addr.s_addr = ip_header->saddr;

  // Return the ,,, value
  return inet_ntoa(source.sin_addr);
}

int net_bind_socket_to_iface(int socket, char* iface) {
    return setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface));
}

int net_initialize_server_socket() {
    // Create the server socket.
    int socket_server = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_server < 0) {
        syslog(LOG_EMERG, "Server socket creation has failed.");
        return -1;
    }

    // Bind the server socket.
    struct sockaddr_in server_address;
    bzero((char *)&server_address, sizeof(server_address));

    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_family      = AF_INET;
    server_address.sin_port        = htons(NET_SERVER_PORT);

    if(bind(socket_server, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        syslog(LOG_EMERG, "Server socket binding has failed.");
        return -1;
    }

    return socket_server;
}

int net_accept_connection(int socket_server) {
    struct sockaddr_in client_address;
    socklen_t client_address_size = sizeof(client_address);

    int socket_client = accept(socket_server, (struct sockaddr *)&client_address, &client_address_size);

    if(socket_client < 0) {
      syslog(LOG_EMERG, "Error: cannot accept the connection.");

      return -1;
    }

    return socket_client;
}

int net_create_sniffing_socket() {
    int socket_sniff = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if(socket_sniff < 0) {
      syslog(LOG_EMERG, "Error: unable to create sniffing socket!");


      return -1;
    }

    return socket_sniff;
}
