#include "./../../includes/ft_ping.h"
/*
ICMP PACKET DETAILS
An IP header without options is 20 bytes.
An ICMP ECHO_REQUEST packet contains an additional 8 bytes worth of ICMP header
followed by an arbitrary amount of data. When a packetsize is given,
this indicated the size of this extra piece of data (the default is 56).
Thus the amount of data received inside of an IP packet of type ICMP ECHO_REPLY
will always be 8 bytes more than the requested data space (the ICMP header).
*/

int send_ping(int socket_fd, unsigned long host, double *start) {
	static int seq = 0;
	
	// destination
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));

	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = host;

	// buff will be my packet
	unsigned char packet[PACKET_SIZE];
	// construct header
	struct icmphdr *icmp = (struct icmphdr *)(packet);
	// Payload
	memset(packet + sizeof(struct icmphdr), '1', PAYLOAD_SIZE);
	// icmp structure
	icmp->type = ICMP_ECHO; // Type 8
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = seq++;
	icmp->un.echo.id = getpid();
	// Calculate checksum from icmp header and payload
	icmp->checksum = calculate_checksum((unsigned short *)packet, PACKET_SIZE);
	// send packet
	*start = get_time_val();
	int status = sendto(socket_fd, packet, sizeof(packet), 0, (struct sockaddr *)&dst, sizeof(dst));
	if (status < 0) {
		perror("Error sending packet\n");
		return 1;
	}
	return 0;
}

int recv_ping(int socket_fd, char *ip_str, double *start, double *end, unsigned char flag) {
	unsigned char buffer[sizeof(struct iphdr) + sizeof(struct icmphdr) + PAYLOAD_SIZE];
	struct sockaddr saddr;
	socklen_t saddr_len = sizeof(saddr);

	memset(buffer, 0, sizeof(buffer));
	int buflen = recvfrom(socket_fd, buffer, sizeof(buffer), 0, &saddr, &saddr_len);
	if (buflen < 0) {
		// perror("Error receiving packet\n");
		return 1;
	}
	struct iphdr *ip = (struct iphdr *)buffer;
	struct icmphdr *icmp = (struct icmphdr *)(buffer + ip->ihl * 4);
	if (icmp->type != ICMP_ECHOREPLY && icmp->un.echo.id != getpid()) { // case ping localhost
		if (flag & FLAG_VERBOSE)
			print_err_icmp_body(buffer);
		print_icmp_err(icmp->type, icmp->code);
		return icmp->type;
	}
	*end = get_time_val();
	if (pingloop)
		printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
			buflen - ip->ihl * 4,
			ip_str,
			icmp->un.echo.sequence,
			ip->ttl,
			*end - *start);
	return 0;
}

void ping_loop(int socket_fd, t_tokens *tokens, double *start, double *end, size_t
	*total_pkgs, size_t *recv_pkgs, t_stats *stats) {

    if (send_ping(socket_fd, ((t_host_info *)(tokens->head->data))->ip.s_addr, start) == 0) {
        (*total_pkgs)++;
        if (recv_ping(socket_fd, ((t_host_info *)(tokens->head->data))->ip_str, start, end, tokens->flags) == 0) {
            (*recv_pkgs)++;
            double diff = *end - *start;
            double *diff_ptr = malloc(sizeof(double));
            if (diff_ptr == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            *diff_ptr = diff;
            lst_add_back(&stats->head, lst_new(diff_ptr));
            set_stats(stats, diff);
        } /*else {
            dprintf(STDERR_FILENO, "Request timeout for icmp_seq %ld\n", total_pkgs - 1);
        }*/
    }
    if (pingloop)
    	sleep(INTERVAL);
}


unsigned short calculate_checksum(unsigned short *packet, size_t len) {
	unsigned short *buf = packet;
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
	return ~sum;
}

double	get_time_val(void)
{
	struct timeval	time;

	gettimeofday(&time, NULL);
    return (double)time.tv_sec * 1000.0 + (double)time.tv_usec / 1000.0;
}

void ft_calculate_stats(char *hostname, size_t total_pkgs, size_t recv_pkgs, t_stats stats) {
	printf("--- %s ping statistics ---\n", hostname);
	printf("%ld packets transmitted, %ld received, %.1ld%% packet loss\n",
		total_pkgs,
		recv_pkgs,
		((total_pkgs - recv_pkgs) / total_pkgs) * 100);
	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		stats.min,
		stats.avg,
		stats.max,
		stats.stddev);
}

void set_stats(t_stats *stats, double time) {
	stats->count++;
	stats->total += time;
	stats->min = stats->min == 0 || stats->min > time ? time : stats->min;
	stats->max = stats->max < time ? time : stats->max;
	stats->avg = stats->total / stats->count;
	// Calculate standard deviation
	t_list *aux = stats->head;
	double variance = 0.0;
	while (aux->next != NULL)
	{
		variance += pow(*(double *)aux->data - stats->avg, 2);
		aux = aux->next;
	}
	stats->stddev = sqrt(variance / stats->count);
}