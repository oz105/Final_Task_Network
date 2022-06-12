#include <pcap.h>
        #include <stdio.h>
        #include <arpa/inet.h>

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
        u_short ether_protocol_type;
        };


        // tcp header
        struct tcp_header
        {
        unsigned short th_src_port;
        unsigned short th_dest_port;
        unsigned char th_offx2;  // data offset
        unsigned char th_flags;
        unsigned short th_win;
        unsigned short th_check_sum;
        unsigned short th_urp; // urgent pointer
        };

        void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
        {
        int i=0;
        int size_data=0;
        struct ethheader *eth = (struct ethheader *)packet;

        if (ntohs(eth->ether_protocol_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *)
        (packet + sizeof(struct ethheader));
        struct tcp_header *tcp = (struct tcp_header *)(packet+sizeof(struct ethheader) + sizeof(struct ipheader));


        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));

        // switch cases to choosen protocol type
        switch(ip->iph_protocol) {
        case IPPROTO_TCP:
        printf("   Protocol: TCP\n");
        printf("   src port: %d\n", ntohs(tcp->th_src_port));
        printf("   dst port: %d\n", ntohs(tcp->th_dest_port));
        break;
        case IPPROTO_UDP:
        printf("   Protocol: UDP\n");
        break;
        case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        break;
default:
        printf("   Protocol: others\n");
        break;
        }

        char *data = (u_char *)packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcp_header);
        size_data = ntohs(ip->iph_packet_length) - (sizeof(struct ipheader) +sizeof(struct tcp_header));
        if(size_data>0){
        printf("   Payload (%d bytes):\n", size_data);
        for(i=0; i<size_data; i++){
        if(isprint(*data))
        printf("%c", *data);
        else
        printf(".");
        data++;

        }
        }
        }
        return;
        }

        int main()
        {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        char filter_exp[] = "proto TCP and (host 10.0.2.5 and 10.0.2.15) portrange 10-100";
        bpf_u_int32 net;

        // the first step is to open live pcap session on NIC with name enp0s3
        handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

        // the second step is to compile filter_exp into BPF psuedo-code
        pcap_compile(handle, &fp, filter_exp, 0, net);
        pcap_setfilter(handle, &fp);

        // the third step is to capture packets
        pcap_loop(handle, -1, got_packet, NULL);

        pcap_close(handle);   //kast thing we do is to close the handle
        return 0;
        }
