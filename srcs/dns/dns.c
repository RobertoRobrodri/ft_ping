#include "./../../includes/ft_ping.h"

struct in_addr dns_look_up(char **host) {
	struct addrinfo hints, *result;

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
	struct in_addr ip = addr->sin_addr;
	// Change host to canonical name
	size_t ai_canonname_len = strlen(result->ai_canonname);
	memset(*host, 0, ai_canonname_len + 1);
	memcpy(*host, result->ai_canonname, ai_canonname_len);
	freeaddrinfo(result);
	return ip;
}