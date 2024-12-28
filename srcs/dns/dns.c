#include "./../../includes/ft_ping.h"

t_host_info *dns_look_up(char **host) {
	struct addrinfo hints, *result;
	t_host_info *ret = malloc(sizeof(t_host_info));

	if (ret == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;
	hints.ai_socktype = SOCK_DGRAM;
	int status = getaddrinfo(*host, NULL, &hints, &result); 
	if (status != 0) {
        dprintf(STDERR_FILENO, "Error getting address info: %s\n", gai_strerror(status));
		exit(-1);
	}
	struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
	ret->ip = addr->sin_addr;
	ret->hostname = strdup(result->ai_canonname);
	inet_ntop(AF_INET, &ret->ip, ret->ip_str, INET_ADDRSTRLEN);
	freeaddrinfo(result);
	return ret;
}