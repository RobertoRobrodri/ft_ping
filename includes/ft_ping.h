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

#define TTL 63
#define TIMEOUT 1
#define PAYLOAD_SIZE 56
#define PACKET_SIZE sizeof(struct icmphdr) + PAYLOAD_SIZE

#ifndef INTERVAL
#define INTERVAL 1
#endif

typedef struct s_timeval{
	double timeval;
	struct s_timeval *next;
} t_timeval;

typedef struct s_stats{
	size_t count;

	double min;
	double max;
	double total;
	double avg;
	double stddev;
	t_timeval *head;
} t_stats;

void ping_loop(int socket_fd, struct in_addr host, char *hostname);
int send_ping(int socket_fd, unsigned long host, double *start);
int recv_ping(int socket_fd, char *ip_str, double *start, double *end);

unsigned short calculate_checksum(unsigned short *packet, size_t len);

struct in_addr dns_look_up(char **host);

void signal_handler(int sig);

double	get_time_val(void);
void ft_calculate_stats(char *hostname, size_t total_pkgs, size_t recv_pkgs, t_stats stats);
void set_stats(t_stats *stats, double time);

t_timeval *lst_new(double timeval);
void lst_add_back(t_timeval **lst, t_timeval *new);
void free_list(t_timeval **lst);

extern bool pingloop;