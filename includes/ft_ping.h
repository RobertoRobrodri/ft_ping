#pragma once

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <limits.h>
#include <math.h>
#include <sys/time.h>


#define TTL 64
#define TIMEOUT 64
#define PAYLOAD_SIZE 56
#define PACKET_SIZE sizeof(struct icmphdr) + PAYLOAD_SIZE

#ifndef INTERVAL
#define INTERVAL 1
#endif

#define FLAG_VERBOSE (1 << 1)  // bit 0
#define FLAG_HELP    (1 << 2)  // bit 1

typedef struct s_list {
    void *data;
    struct s_list *next;
} t_list;

typedef struct s_stats {
	size_t count;

	double min;
	double max;
	double total;
	double avg;
	double stddev;
	t_list *head;
} t_stats;

typedef struct s_host_info {
	char *hostname;
	char ip_str[INET_ADDRSTRLEN];
	struct in_addr ip;
} t_host_info;

typedef struct s_tokens {
	unsigned char flags;
	t_list *head;
} t_tokens;

void ping_loop(int socket_fd, t_tokens *tokens, double *start, double *end, \
	size_t *total_pkgs, size_t *recv_pkgs, t_stats *stats);
int send_ping(int socket_fd, unsigned long host, double *start);
int recv_ping(int socket_fd, char *ip_str, double *start, double *end, unsigned char flag);

unsigned short calculate_checksum(unsigned short *packet, size_t len);

t_host_info *dns_look_up(char *host);

void signal_handler(int sig);

double	get_time_val(void);
void ft_calculate_stats(char *hostname, size_t total_pkgs, size_t recv_pkgs, t_stats stats);
void set_stats(t_stats *stats, double time);

t_list *lst_new(void *data);
void lst_add_back(t_list **lst, t_list *new);
void free_list(t_list **lst);
void free_list_data(t_list **lst);

extern bool pingloop;