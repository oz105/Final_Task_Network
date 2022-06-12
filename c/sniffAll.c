// sniff all
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dest_host[6];
  u_char  ether_src_host[6];
  u_short ether_protocol_type; 
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ih_length:4, 
                     iph_version:4; 
  unsigned char      iph_tos; // type of service
  unsigned short int iph_header_length; //for data and header
  unsigned short int iph_ident; // identification
  unsigned short int iph_flag:3,
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; 
  unsigned char      iph_protocol_type; 
  unsigned short int iph_checksum; 
  struct  in_addr    iph_srcip; 
  struct  in_addr    iph_dstip;   
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_protocol_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_srcip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_dstip));    

    /* determine protocol */
    switch(ip->iph_protocol_type) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); 
return 0;
}
