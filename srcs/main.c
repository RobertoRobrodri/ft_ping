#include "./../includes/ft_ping.h"

bool pingloop = true;

static void parse_tokens(int argc, char **argv, t_tokens *tokens) {
    for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			for (int j = 1; argv[i][j]; j++) {
				if (argv[i][j] == 'v')
					tokens->flags |= FLAG_VERBOSE;
				else if (argv[i][j] == '?')
					tokens->flags |= FLAG_HELP;
				else {
					dprintf(STDERR_FILENO, "ping: invalid option -- '%c'\n", argv[i][j]);
					dprintf(STDERR_FILENO, "Try 'ping -?' for more information.\n");
				}
		}
        } else
            lst_add_back(&tokens->head, lst_new(argv[i]));
    }
}


static int ft_ping(t_tokens *tokens) {
	int socket_fd;
	int ttl = TTL;
	struct timeval timeout = {TIMEOUT, 0};

	// Create raw socket
	if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		printf("Error creating socket\n");
		return 1;
	}
	if (setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("Error setting IP_TTL\n");
		return 1;
	};
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("Error setting IP_TOS\n");
		return 1;
	};
	t_list *aux = tokens->head;
	tokens->head->data = (void *)dns_look_up((char *)tokens->head->data);
	print_header(tokens);
	
	double start, end;
    size_t total_pkgs = 0, recv_pkgs = 0;
    t_stats stats = {0, 0, 0, 0, 0, 0, NULL};
	while (tokens->head) {
		ping_loop(socket_fd, tokens, &start, &end, &total_pkgs, &recv_pkgs, &stats);
		if (pingloop)
			continue;
		ft_calculate_stats(((t_host_info *)(tokens->head->data))->hostname, total_pkgs, recv_pkgs, stats);
        free_list(&stats.head);
        total_pkgs = 0;
        recv_pkgs = 0;
        stats = (t_stats) {0, 0, 0, 0, 0, 0, NULL};
		tokens->head = tokens->head->next;
		if (tokens->head)
			print_header(tokens);
	}
	tokens->head = aux;
	close(socket_fd);
	return 0;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		dprintf(STDERR_FILENO, "ping: missing host operand\n");
		dprintf(STDERR_FILENO, "Try 'ping -?' for more information.\n");
		return 1;
	}
	if (getuid() != 0) {
		dprintf(STDERR_FILENO, "Require root\n");
		return 1;
	}
	signal(SIGINT, signal_handler);
	t_tokens tokens = {1, NULL};
	parse_tokens(argc, argv, &tokens);
	if (tokens.flags & FLAG_HELP) {
		print_usage();
		exit(EXIT_SUCCESS);
	}
	ft_ping(&tokens);
	free_list_data(&tokens.head);
	return EXIT_SUCCESS;
}