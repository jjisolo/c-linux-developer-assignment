#include "net.h"
#include "buf.h"

// Vector that holds data about the IP address and how
// many times that IP occured at the sniffing stage.
static ip_vec_t   ip_vector;
static bool       do_sniffing;
static pthread_t  sniffer_thread;
static int        binded_sniffing_socket;

void net_init() {
    iv_vec_create(&ip_vector);
}

void net_release() {
    close(binded_sniffing_socket);

    iv_vec_release(&ip_vector);
}

char* net_get_dest_ip(unsigned char *buffer) {
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

void net_bind_sniffer_socket(int socket) {
    binded_sniffing_socket = socket;
}

void net_start_sniffing() {
    do_sniffing = true;

    pthread_create(&sniffer_thread, NULL, &net_sniff_ip_addresses, NULL);
}

void net_stop_sniffing() {
    do_sniffing = false;

    pthread_join(sniffer_thread, NULL);
}

void* net_sniff_ip_addresses(void * arg) {
    unsigned char packet_buffer[2048];

    // Setup datastructures for the recv function.
    struct sockaddr socket_address;
    int             recv_data_size;
    socklen_t       socket_address_size = sizeof(socket_address);

    char*  ip_address_dynamic;
    char*  ip_address;
    size_t ip_address_len;

    while(do_sniffing) {
        // Sniff the packets if the corresponding mode is ebabled.
        recv_data_size = recvfrom(binded_sniffing_socket, packet_buffer, 2048, 0, &socket_address, &socket_address_size);
        if(recv_data_size < 0) {
          syslog(LOG_ERR, "Error: recvfrom() failed to get packets!");

          return NULL;
        }

        // Get the destination IP form the packet header.
        ip_address     = net_get_dest_ip(packet_buffer);
        ip_address_len = strlen(ip_address);

        if(ip_address_len >= 2) {
            ip_address[strlen(ip_address)  ] = '\0';
            ip_address[strlen(ip_address)-1] = '\0';
        }

        // Workaround to store the ip-address string in the vector.
        ip_address_dynamic = (char *)malloc(ip_address_len+1);
        strcpy(ip_address_dynamic, ip_address);

        // Get the destination IP address from the recieved packet and store it in the vector.
        iv_vec_push(&ip_vector, ip_address_dynamic);
    }

    return NULL;
}
