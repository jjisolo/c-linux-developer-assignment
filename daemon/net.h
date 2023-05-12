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

#define NET_SERVER_PORT 8838

char* net_get_dest_ip(unsigned char *buffer, int size);

int net_bind_socket_to_iface(int socket, char* iface);

int net_initialize_server_socket();

int net_accept_connection(int socket_server);

int net_create_sniffing_socket();

#endif //__WORK_TASK_NET_H_INCLUDED__
