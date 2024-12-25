#include "./../../includes/ft_ping.h"

void signal_handler(int sig) {
	if (sig == SIGINT)
		pingloop = false;
}