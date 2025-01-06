#include "./../../includes/ft_ping.h"

void print_icmp_err(int type, int code) {
	switch (type) {
	case ICMP_DEST_UNREACH:
		switch(code) {
		case ICMP_NET_UNREACH:
			printf("Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			printf("Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			printf("Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			printf("Frag needed\n");
			break;
		case ICMP_SR_FAILED:
			printf("Source Route Failed\n");
			break;
		case ICMP_NET_UNKNOWN:
			printf("Destination Net Unknown\n");
			break;
		case ICMP_HOST_UNKNOWN:
			printf("Destination Host Unknown\n");
			break;
		case ICMP_HOST_ISOLATED:
			printf("Source Host Isolated\n");
			break;
		case ICMP_NET_ANO:
			printf("Destination Net Prohibited\n");
			break;
		case ICMP_HOST_ANO:
			printf("Destination Host Prohibited\n");
			break;
		case ICMP_NET_UNR_TOS:
			printf("Destination Net Unreachable for Type of Service\n");
			break;
		case ICMP_HOST_UNR_TOS:
			printf("Destination Host Unreachable for Type of Service\n");
			break;
		case ICMP_PKT_FILTERED:
			printf("Packet filtered\n");
			break;
		case ICMP_PREC_VIOLATION:
			printf("Precedence Violation\n");
			break;
		case ICMP_PREC_CUTOFF:
			printf("Precedence Cutoff\n");
			break;
		default:
			printf("Dest Unreachable, Bad Code: %d\n", code);
			break;
		}
		break;
	case ICMP_SOURCE_QUENCH:
		printf("Source Quench\n");
		break;
	case ICMP_REDIRECT:
		switch(code) {
		case ICMP_REDIR_NET:
			printf("Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			printf("Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			printf("Redirect Type of Service and Host");
			break;
		default:
			printf("Redirect, Bad Code: %d", code);
			break;
		}
		break;
	}
}

void print_err_icmp_body(uint8_t *buf) {
	struct iphdr *ipb = (struct iphdr *)buf;
	struct icmphdr *icmpb = (struct icmphdr *)(buf + ipb->ihl * 4);
	uint8_t *bytes = (uint8_t *)ipb;
	char str[INET_ADDRSTRLEN];

	printf("IP Hdr Dump:\n");
	for (size_t i = 0; i < sizeof(struct iphdr); i += 2) {
		printf(" %02x%02x", *bytes, *(bytes + 1));
		bytes += 2;
	}
	printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src	"
	       "Dst	Data\n");
	printf(" %x  %x  %02x %04x %04x   %x %04x  %02x  %02x %04x ",
	       ipb->version, ipb->ihl, ipb->tos, ntohs(ipb->tot_len),
	       ntohs(ipb->id), ntohs(ipb->frag_off) >> 13,
	       ntohs(ipb->frag_off) & 0x1FFF, ipb->ttl, ipb->protocol,
	       ntohs(ipb->check));
	inet_ntop(AF_INET, &ipb->saddr, str, sizeof(str));
	printf("%s  ", str);
	inet_ntop(AF_INET, &ipb->daddr, str, sizeof(str));
	printf("%s\n", str);
	printf("ICMP: type %x, code %x, size %zu, id %#04x, seq 0x%04x\n",
	       icmpb->type, icmpb->code, PACKET_SIZE,
	       icmpb->un.echo.id, icmpb->un.echo.sequence);
}

void print_header(t_tokens *tokens) {
	printf("PING %s (%s): %d data bytes",((t_host_info *)(tokens->head->data))->hostname,
		((t_host_info *)(tokens->head->data))->ip_str,
		PAYLOAD_SIZE);
	if (tokens->flags & FLAG_VERBOSE) {
		int pid = getpid();
		printf(", id 0x%04x = %d", pid, pid);
	}
	printf("\n");
}

void print_usage(void) {
	printf("Usage: ping [OPTION...] HOST ...\n");
	printf("Send ICMP ECHO_REQUEST packets to network hosts.\n");
	printf("Options:\n");
	printf("-v verbose output\n");
	printf("-? give this help list\n");
}