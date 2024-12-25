#include "./../includes/ft_ping.h"

bool pingloop = true;

static int ft_ping(struct in_addr host, char *hostname) {
	int socket_fd;
	int ttl = TTL;
	struct timeval timeout = {TIMEOUT, 0};

	// Create raw socket
	if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		printf("Error creating socket\n");
		return 1;
	}
	// If you use this option, you have to construct the IP header
	// if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
	// 	perror("Error setting IP_HDRINCL\n");
	// 	return 1;
	// };
	if (setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("Error setting IP_TTL\n");
		return 1;
	};
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("Error setting IP_TOS\n");
		return 1;
	};
	ping_loop(socket_fd, host, hostname);
	close(socket_fd);
	return 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Print usage\n"); // TODO print usage
		return 1;
	}
	// TODO parse options
	signal(SIGINT, signal_handler);
	struct in_addr ip = dns_look_up(&argv[1]);
	return ft_ping(ip, argv[1]);
}