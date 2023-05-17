#include "net.h"

// Vector that holds data about the IP address and how
// many times that IP occured at the sniffing stage.
#define NET_SOCKET_IFACE_BUFFER_MAX_LEN 20
#define NET_SOCKET_DEFAULT_IFACE        "eth0"

static pthread_t  sniffer_thread;
static ip_vec_t   ip_vector;
static bool       do_sniffing;
static int        binded_sniffing_socket;
static char*      binded_iface;

void net_init() {
    do_sniffing = false;

    binded_iface = (char *)calloc(NET_SOCKET_IFACE_BUFFER_MAX_LEN, sizeof(char));
    strcpy(binded_iface, NET_SOCKET_DEFAULT_IFACE);

    iv_vec_create(&ip_vector);
}

void net_release() {
    if(do_sniffing)
        net_stop_sniffing();

    // If the user somehow managed to delete the
    // binded vector.
    if(ip_vector._data) {
        syslog(LOG_DEBUG, "Dumping information for iface %s..", binded_iface);
        fs_dump_ip_data(binded_iface, &ip_vector);
        iv_vec_release(&ip_vector);
    }

    close(binded_sniffing_socket);
    free (binded_iface);
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
    if(do_sniffing)
        return -1;

    if(iface == NULL)
        return -1;

    if(strlen(iface) > NET_SOCKET_IFACE_BUFFER_MAX_LEN)
        return -1;

    // If the iface is the same as the current
    if(strcmp(iface, binded_iface) != 0) {
        if(do_sniffing)
           net_stop_sniffing();

        syslog(LOG_DEBUG, "Binding iface (%s => %s)", binded_iface, iface);
        if(setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) == 0) {
            syslog(LOG_DEBUG, "Dumping %s information..", binded_iface);
            fs_dump_ip_data(binded_iface, &ip_vector);

            syslog(LOG_DEBUG, "Loading %s information...", iface);
            fs_load_ip_data(iface,        &ip_vector);

            strcpy(binded_iface, iface);
            binded_iface[strlen(iface)] = '\0';
            return 0;
        }

        syslog(LOG_DEBUG, "Settings socket option failed for %s", iface);
        return 0;
    }

    return -1;
}

int net_initialize_server_socket() {
    int socket_server;

    // Create the server socket.
    if((socket_server = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
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

long net_get_ip_count(char* ip_address) {
    size_t element_index;

    // If the element was not found.
    if(((element_index = iv_vec_find(&ip_vector, ip_address))) == -1) {
        return element_index;
    }

    // Element is found!
    return ip_vector._data[element_index].ip_address_num;
}

int net_accept_connection(int socket_server) {
    struct sockaddr_in client_address;
    int                socket_client;
    socklen_t          client_address_size = sizeof(client_address);

    if((socket_client = accept(socket_server, (struct sockaddr *)&client_address, &client_address_size)) < 0) {
      syslog(LOG_EMERG, "Error: cannot accept the connection.");
      return -1;
    }

    return socket_client;
}

int net_create_sniffing_socket() {
    int socket_sniff;

    if((socket_sniff = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
      syslog(LOG_EMERG, "Error: unable to create sniffing socket!");
      return -1;
    }

    return socket_sniff;
}

char* net_get_binded_iface() {
    return binded_iface;
}

ip_vec_t net_get_binded_ip_vector() {
    return ip_vector;
}

void net_bind_sniffer_socket(int socket) {
    binded_sniffing_socket = socket;
}

void net_start_sniffing() {
    do_sniffing = true;

    pthread_create(&sniffer_thread, NULL, &net_sniff_ip_addresses, NULL);
}

void net_stop_sniffing() {
    syslog(LOG_DEBUG, "Stopped sniffing on iface %s", binded_iface);
    do_sniffing = false;

    pthread_join(sniffer_thread, NULL);
}

void* net_sniff_ip_addresses(void * arg) {
    if(!ip_vector._data) {
        syslog(LOG_ERR, "Error: cannot sniff ip addresses! the ip_vector is not initialized");
        return NULL;
    }

    unsigned char packet_buffer[2048];

    // Setup datastructures for the recv function.
    struct sockaddr socket_address;
    int             recv_data_size;
    socklen_t       socket_address_size = sizeof(socket_address);

    char*  ip_address_dynamic;
    char*  ip_address;
    size_t ip_address_len;

    syslog(LOG_DEBUG, "Started sniffing on iface %s", binded_iface);
    while(do_sniffing) {
        // Sniff the packets if the corresponding mode is ebabled.
        if((recv_data_size = recvfrom(binded_sniffing_socket, packet_buffer, 2048, 0, &socket_address, &socket_address_size)) < 0) {
          syslog(LOG_ERR, "Error: recvfrom() failed to get packets!");
          return NULL;
        }

        // Get the destination IP form the packet header.
        ip_address     = net_get_dest_ip(packet_buffer);
        ip_address_len = strlen(ip_address);

        if(ip_address_len >= 1)
            ip_address[ip_address_len] = '\0';

        // Workaround to store the ip-address string in the vector.
        ip_address_dynamic = (char *)malloc(ip_address_len+1);
        strcpy(ip_address_dynamic, ip_address);

        // Get the destination IP address from the recieved packet and store it in the vector.
        iv_vec_push(&ip_vector, ip_address_dynamic);
    }

    return NULL;
}
