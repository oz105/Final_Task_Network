#include <pcap.h>
        #include <stdio.h>
        #include <arpa/inet.h>
        #include <linux/tcp.h>
        #include <string.h>

        #define ETHER_ADDR_LEN 6

        // ip header
        struct ipheader {
        unsigned char      iph_ih_length:4,
        ip_version:4;
        unsigned char      iph_tos;
        unsigned short int iph_packet_length; //the length of data and header
        unsigned short int iph_ident;
        unsigned short int iph_flag:3,
        iph_offset:13;
        unsigned char      iph_ttl;
        unsigned char      iph_protocol;
        unsigned short int iph_chksum;
        struct  in_addr    iph_sourceip;
        struct  in_addr    iph_destip;
        };


        // ethernet header
        struct ethheader {
        u_char  ether_dest_host_addr[6];
        u_char  ether_src_host_addr[6];
        u_short ether_protocol_type; // IP? ARP? RARP? etc
        };


        // icmp header
        struct icmpheader {
        unsigned char icmp_message_type;
        unsigned char icmp_error_code;
        unsigned short int icmp_chksum;
        unsigned short int icmp_request_id;
        unsigned short int icmp_seq;

        unsigned char timestamp[8];
        };


        void send_raw_ip_packet(struct ipheader* ip) {
        struct sockaddr_in dest_info;
        int enable = 1;

        // the first step is to create a raw network socket
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

        // the second step is to set socket option
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

        // the third step is to Provide needed info about destination
        dest_info.sin_family = AF_INET;
        dest_info.sin_addr = ip->iph_destip;

        // the fourth step is to send the packet out
        sendto(sock, ip, ntohs(ip->iph_packet_length), 0, (struct sockaddr*)&dest_info, sizeof(dest_info));

        close(sock);
        }

        void send_echo_reply(struct ipheader * ip) {
        int ip_header_len = ip->iph_ih_length * 4;
        const char buffer[1500];

        // make copy from original packet
        memset((char *)buffer, 0, 1500);
        memcpy((char *)buffer, ip, ntohs(ip->iph_packet_length));
        struct ipheader* newip = (struct ipheader*) buffer;
        struct icmpheader* newicmp = (struct icmpheader*) (buffer + sizeof(ip_header_len));

        // consturct IP swap source and destination to fake the echo response
        newip->iph_sourceip = ip->iph_destip;
        newip->iph_destip   = ip->iph_sourceip;
        newip->iph_ttl = 64;

        // icmp echo response- ping is type 0
        newicmp->icmp_message_type = 0;

        send_raw_ip_packet(newip);
        }

        void got_packet(u_char *args, const struct pcap_pkthdr * header, const u_char *packet)
        {
        struct ethheader *eth = (struct ethheader*) packet;

        if(ntohs(eth->ether_protocol_type) == 0x0800) { // 0x0800 = IP TYPE
        struct ipheader *ip = (struct ipheader*) (packet + sizeof(struct ethheader));
        struct tcphdr *tcp  = (struct tcphdr*) ((u_char*) ip + sizeof(struct ipheader));

        unsigned short pktlen = ntohs(ip->iph_packet_length);

        printf("\t FROM: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("\t TO: %s\n", inet_ntoa(ip->iph_destip));

        switch(ip->iph_protocol) {
        case IPPROTO_TCP:
        printf(" Protocol: TCP\n");
        return;
        case IPPROTO_UDP:
        printf(" Protocol: UDP\n");
        return;
        case IPPROTO_ICMP:
        printf(" Protocol: ICMP\n");
        send_echo_reply(ip);
        return;
default:
        printf(" Protocol: other\n");
        return;
        }

        }
        }

        int main()
        {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        char filter_exp[] = "proto ICMP and (host 1.2.3.4 and 10.0.2.15)" ;
        bpf_u_int32 net;

        handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

        pcap_compile(handle, &fp, filter_exp, 0, net);
        pcap_setfilter(handle, &fp);

        pcap_loop(handle, -1, got_packet, NULL);

        pcap_close(handle);
        return 0;
        }
