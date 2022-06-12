#include <unistd.h>
        #include <stdio.h>
        #include <string.h>
        #include <sys/socket.h>
        #include <netinet/ip.h>
        #include <arpa/inet.h>

        #include "myheader.h"

        void send_raw_ip_packet(struct ipheader* ip){

        struct sockaddr_in dest_info;
        int valid = 1;
	//create a raw socket
        int sock= socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        
        //set socket option
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &valid, sizeof(valid));

	//provide the info on the des
        dest_info.sin_family = AF_INET;
        dest_info.sin_addr = ip->iph_destip;

        printf("sending packet...\n");
        
        //send the packet
        sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
        
        if(sendto(sock,ip,ntohs(ip->iph_len),0,(struct sockaddr *)&dest_info,sizeof(dest_info))<0){
        	perror("packet not sent\n");
        	return;
        }
        else{
        printf("\n--------------------------------------------\n");
        printf(" 	From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf(" 	To: %s\n", inet_ntoa(ip->iph_destip));
        printf("\n--------------------------------------------\n");
        }
        close(sock);
        }
        unsigned short in_cksum (unsigned short *buf, int length){

        unsigned short *w = buf;
        int left = length;
        int counter = 0;
        unsigned short temp = 0;

        while(left>1){
        counter+=*w++;
        left-=2;
        }

        if(left == 1){
        *(u_char *)(&temp) = *(u_char *)w;
        counter+= temp;
        }

        counter = (counter>>16)+(counter & 0xffff);
        counter+=(counter>>16);
        return (unsigned short)(~counter);
        }






	// spoof icmp set src 1.1.1.1
        int main() {
        char buff[1500];

        memset(buff, 0, 1500);

        
        //Fill the ICMP header.
        
        struct icmpheader *icmp = (struct icmpheader *)
        (buff + sizeof(struct ipheader));
        icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

        // Calculate the checksum for integrity
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
        sizeof(struct icmpheader));

 
        //Fill in the IP header.
   
        struct ipheader *ip = (struct ipheader *) buff;
        ip->iph_ver = 4;
        ip->iph_ihl = 5;
        //ip->iph_tos = 16;
        //ip->iph_ident = htons(54321);
        ip->iph_ttl = 64;
        ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
        ip->iph_destip.s_addr = inet_addr("10.0.2.15");
        ip->iph_protocol = IPPROTO_ICMP;
        //ip->iph_len=htons(1500);
        ip->iph_len= htons(sizeof(struct ipheader) +sizeof(struct icmpheader));
        
         //Send the spoofed packet
 
        send_raw_ip_packet (ip);

        return 0;
        }
