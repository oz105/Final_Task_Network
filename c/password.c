#include <pcap.h>
        #include <stdio.h>
        #include <arpa/inet.h>
        #include <string.h>
        #include <sys/socket.h>
        #include <netinet/ip.h>
        #include <linux/if_packet.h>

        #include <net/ethernet.h>
// IP Header
        struct ipheader {
        unsigned char      iph_ihl:4, //IP header length
        iph_ver:4; //IP version
        unsigned char      iph_tos; //Type of service
        unsigned short int iph_len; //IP Packet length (data + header)
        unsigned short int iph_ident; //Identification
        unsigned short int iph_flag:3, //Fragmentation flags
        iph_offset:13; //Flags offset
        unsigned char      iph_ttl; //Time to Live
        unsigned char      iph_protocol; //Protocol type
        unsigned short int iph_chksum; //IP datagram checksum
        struct  in_addr    iph_sourceip; //Source IP address
        struct  in_addr    iph_destip;   //Destination IP address
        };

// Ethernet header
        struct ethheader {
        u_char  ether_dhost[6]; // dst host address
        u_char  ether_shost[6]; // src host address
        u_short ether_type;     // protocol type
        };

        /* TCP header */
        typedef unsigned int tcp_seq;

        struct tcpheader {
        unsigned short th_sport; // src
        unsigned short th_dport; // dst
        tcp_seq th_seq;          // sequence number
        tcp_seq th_ack;          // acknowledgement number
        unsigned char  th_offx2; // data offset
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        unsigned char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        unsigned short th_win;                 // window
        unsigned short th_sum;                 // checksum
        unsigned short th_urp;                 // urgent pointer
        };

        void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
        {
        char *data;
        struct ethheader *eth = (struct ethheader *)packet;

        if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader * ip = (struct ipheader *)
        (packet + sizeof(struct ethheader));

        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));

        int sizeEthernet = 14;
        int sizeIp = (ip->iph_ihl)*4;
        struct tcpheader *tcp = (struct tcpheader*)(packet + sizeEthernet + sizeIp);
        int sizeTcp = TH_OFF(tcp)*4;
        data = (unsigned char*)(packet + sizeEthernet + sizeIp + sizeTcp);
        int sizeData = ntohs(ip->iph_len) - (sizeIp + sizeTcp);
        printf("      Data: \n");
        for(int i=0 ; i<sizeData ; i++)
        {
        printf("%c",*(data+i));
        }
        }
        }



        int main()
        {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        char filter_exp[] = "proto TCP and dst portrange 10-100";
        bpf_u_int32 net;

        // the first step is to open live pcap session on NIC with name enp0s3
        handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

        // the second step is to compile filter_exp into BPF psuedo-code
        pcap_compile(handle, &fp, filter_exp, 0, net);
        pcap_setfilter(handle, &fp);

        // the third step is to capture packets
        pcap_loop(handle, -1, got_packet, NULL);

        pcap_close(handle);   //close the handle
        return 0;
        }
