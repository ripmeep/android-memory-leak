#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>


void hexdump(const char * s, size_t len, size_t row_len, int show_chars, int colors);

unsigned int Create80211Beacon(uint8_t *buf, size_t len, int radiotap_type, char *addr1, char *bssid, int ssid_len) {
	if (len <= 47) {
		return 0;
	}

	char swap[2];
	int index = 0, ii;

	memset(swap, '\0', sizeof(swap));

	buf[index++] = 0x00;
	buf[index++] = 0x00;

	buf[index++] = (uint8_t)radiotap_type;

	buf[index++] = 0x00;
	buf[index++] = 0x00;
	buf[index++] = 0x00;
	buf[index++] = 0x00;
	buf[index++] = 0x00;

	buf[index++] = 0x80;

	buf[index++] = 0x00;
	buf[index++] = 0x00;
	buf[index++] = 0x00;

	for (int i = 0; i < 6; ++i) {
		memcpy(swap, addr1+(i*2), sizeof(swap));
		ii = index;
		buf[ii+i] = (uint8_t)strtoul(swap, NULL, 16);
		memset(swap, '\0', sizeof(swap));
	}

	index+= 6;

	buf[index++] = 0x77;
	buf[index++] = 0xCC;
	buf[index++] = 0x44;
	buf[index++] = 0x9F;
	buf[index++] = 0xAA;
	buf[index++] = 0x6D;

	for (int i = 0; i < 6; ++i) {
		memcpy(swap, bssid+(i*2), sizeof(swap));
		ii = index;
		buf[ii+i] = (uint8_t)strtoul(swap, NULL, 16);
		memset(swap, '\0', sizeof(swap));
	}

	index += 6;


	for (int i = 0; i < 10; ++i) {
		ii = index;
		buf[ii+i] = 0x00;
	}

	index += 10;

	buf[index++] = 0x64;
	buf[index++] = 0x00;
	buf[index++] = 0x11;
	buf[index++] = 0x00;
	buf[index++] = 0x00;
	buf[index++] = ssid_len;
	buf[index++] = 255;

	return (unsigned int)index & 0xFF;
}


int main(int argc, char ** argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s [DEVICE NAME]\n", argv[0]);
		return -1;
	}

	char *device;
	struct sockaddr_ll ll;
	struct ifreq ifr;
	int sockfd, i = 0;

	device = argv[1];
	assert(sizeof(ifr.ifr_name) == IFNAMSIZ);

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sockfd < 0) {
		fprintf(stderr, "Failed to create raw socket (%d)\n", sockfd);
		perror("Last std error");

		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
		fprintf(stderr, "ioctl() failed on device %s\n", device);
		perror("Last std error");

		close(sockfd);

		return -1;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sockfd, (struct sockaddr*)&ll, sizeof(ll)) < 0) {
		fprintf(stderr, "Interface bind failed on device %s\n", device);
		perror("Last std error");

		close(sockfd);

		return -1;
	}

	uint8_t beacon[128];
	unsigned int beacon_len = Create80211Beacon(beacon, sizeof(beacon), 0x08, "FFFFFFFFFFFF", "704D7BAAFFDD", 25);

	if (beacon_len == 0) {
		fprintf(stderr, "Invalid buffer length for beacon\n");

		close(sockfd);

		return -1;
	}

	printf("[%d] 802.11 Beacon Frame:\n\n", beacon_len);
	hexdump((const char*)beacon, beacon_len, 16, 1, 1);

	while (1) {
		send(sockfd, (char*)beacon, beacon_len, 0);
		printf("\r[%5.d] Beacon broadcasted       ", i++);
		fflush(stdout);
		usleep(10000);
	}

	return 0;
}

void hexdump(const char * s, size_t len, size_t row_len, int show_chars, int colors) {
	int b = 0;
	int xc_offset = 0;
	int cw = 0;
	int is_printable = 0;

	for (int i = 0; i < len; ++i) {
		if (b%row_len == 0)
			printf("[%04x]\t", i);

		if ((isalpha(s[i]) || ispunct(s[i]) || isdigit(s[i])) && colors) {
			is_printable = 1;
			printf("\033[01;9%dm", colors);
		} else
			is_printable = 0;

		printf("%02X\033[0m ", s[i] & 0xFF);

		b++;

		if (b == row_len/2)
			printf("  ");

		if (b%row_len == 0 || i + 1 == len) {
			if (show_chars) {
				for (int p = 0; p < (3*row_len) - (3*b); ++p)
					printf(" ");

				printf("\t| ");

				if (i + 1 == len)
					xc_offset = ((i - row_len) + 1) + (row_len - b);
				else
					xc_offset = (i - row_len) + 1;

				cw = 0;
				for (int x = xc_offset; x < i + 1; ++x) {
					if (isalpha(s[x]) || ispunct(s[x]) || isdigit(s[x]))
						if ((int)s[x] == 0x20)
							printf(".");
						else {
							if (isalpha(s[x]) || ispunct(s[x]) || isdigit(s[x]))
								printf("\033[01;9%dm", colors);
							printf("%c\033[0m", s[x]);
						}
					else
						printf(".");
					cw++;
				}


				for (int p = 0; p < (row_len - cw); ++p)
					printf(" ");

				printf(" |");
			}

			printf("\n");
			b = 0;
		}
	}

	printf("\n");
}
