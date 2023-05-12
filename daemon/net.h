#ifndef __WORK_TASK_NET_H_INCLUDED__
#define __WORK_TASK_NET_H_INCLUDED__

#include <string.h>	
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <pthread.h>

#define NET_SERVER_PORT 8838

// Initialize the subsystem(create the ip<->ip_num vector>
void net_init();

// Release the subsystem(dump the vector, close sockets descriptors)
void net_release();

// Bind requested sniffer socket as an active.
void net_bind_sniffer_socket(int socket);

// Start sniffing.
void net_start_sniffing();

// Stop the sniffing.
void net_stop_sniffing();

// Sniff the ip addresses until net_stop_sniffing() function is
// called.
void* net_sniff_ip_addresses(void *);

// Bind the socket to the iface, and its sniff result to the
// corresponding file in the save/ folder.
int net_bind_socket_to_iface(int socket, char* iface);

// Create socket with specific parameters.
int net_initialize_server_socket();

// Accept the connection for ^this socket.
int net_accept_connection(int socket_server);

// Create socket with specific parameters.
int net_create_sniffing_socket();

// Get the destionation IP from the recieved packet header.
char* net_get_dest_ip(unsigned char *buffer);

#endif //__WORK_TASK_NET_H_INCLUDED__
