/*@TAG(CUSTOM)*/
/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Mathias Buus
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Modifications made by Data61 */

#include <stdio.h>
#include <stdlib.h>
//#include <net/if_packet.h>
#include <net/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <buffer.h>
#include <pcap/pcap.h>
#include "header_struct.h"
#include <porttype.h>
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

//Click realated header
#include <click/camkes_config.hh>
#include <click/config.h>
#include "elements/standard/classifier.hh"
#include "elements/standard/print.hh"
#include <click/element.hh>
#include <click/error.hh>
#include "elements/standard/discard.hh"
#include <iostream>
#include <iomanip>
/* XXX: CAmkES symbols that are linked in after this file is compiled.
   They need to be marked as weak and this is the current hacky way it is done */
extern "C" {
    void *camkes_buffer;
    void camkes_ev_emit(void); 
    void camkes_ev1_wait(void);
    void *camkes_ready;
}
#pragma weak camkes_buffer
#pragma weak camkes_ev_emit
#pragma weak camkes_ev1_wait

void inline debugging(const char* s,int val){
    std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}

void debug_purpose(const u_char* packet,const struct pcap_pkthdr* header){
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("ARP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Reverse ARP\n");
    }   else{
        printf("Unknown type %x\n",ntohs(eth_header->ether_type));
    }
    
    const struct sniff_ip *ip; /* The IP header */

    
    ip = (struct sniff_ip*)(packet+sizeof(struct ether_header));
    printf("Grabbed a packet from ip_src: %s, eth_src: %s \n",inet_ntoa(ip->ip_src),
            ether_ntoa((const ether_addr*)(eth_header->ether_shost)));
    printf("The packet has info as ip_dst: %s, eth_dst: %s\n",
            inet_ntoa(ip->ip_dst),
            ether_ntoa((const ether_addr*)(eth_header->ether_dhost)));
    printf("This packet has a length of %d \n",header->len);
    printf("Ethernet address length is %d\n\n",ETHER_HDR_LEN);


}

/* This function can be used as a callback for pcap_loop() */
void my_packet_handler(
        u_char *args,
        const struct pcap_pkthdr* header,
        const u_char* packet
        ) {
    struct ether_header *eth_header;
    /* The packet is larger than the ether_header struct,
     * but we just want to look at the first part of the packet
     * that contains the header. We force the compiler
     * to treat the pointer to the packet as just a pointer
     * to the ether_header. The data payload of the packet comes
     * after the headers. Different packet types have different header
     * lengths though, but the ethernet header is always the same (14 bytes) */
    eth_header = (struct ether_header *) packet;

    Classifier * clsf = (Classifier *)args;
    debug_purpose(packet,header);

    Packet *p = Packet::make(packet,header->len);
    clsf->push(0,p);
}




int main (int argc, char *argv[]) {

    message_t * buffer_str = (message_t*)camkes_buffer;
    buffer_str->ready = 1;
    snprintf(buffer_str->content, REVERSE_STRING_MAX_LEN, "Hello, World!");
    printf("Sending string: %s\n", buffer_str->content);
    /* Signal the string reverse server and wait for response */
    camkes_ev_emit();
    
    camkes_ev1_wait();
    
    printf("%s\n", buffer_str);

    char errbuf[PCAP_ERRBUF_SIZE]; 

    pcap_t* descr;
//#####################################################################
    char *device;
    char ip[13];
    char subnet_mask[13];

    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;
    struct in_addr address; /* Used for both ip & subnet */


    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        printf("%s\n", errbuf);
        return 1;
    }

    /* Get device info */
    lookup_return_code = pcap_lookupnet(
            device,
            &ip_raw,
            &subnet_mask_raw,
            errbuf
            );
    if (lookup_return_code == -1) {
        printf("%s\n", errbuf);
        return 1;
    }

    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* print error */
        return 1;
    }

    /* Get subnet mask in human readable form */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }

    printf("Device: %s\n", device);
    printf("IP address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);

//####################################################################
// Click relervant code

    
    int re = 0;
    
    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    //Element that discards packet
    Discard discard;
    re = Camkes_config::set_nports(&discard,1,0);
    debugging("setting n ports for discard",re);
    const int din_v[1] = {1};
    Camkes_config::initialize_ports(&discard,din_v,din_v);//We don't have output port putting in_v is fine
    debugging("No configuration call to discard",0);    

    //element that print message
    Print print0;
    Vector<String> print_config0;
    print_config0.push_back("port0");
    re = Camkes_config::set_nports(&print0,1,1);
    debugging("setting n ports for print0",re);
    re = print0.configure(print_config0,&feh);
    debugging("finishing configuration for print0",re);
    const int pin_v[1] = {1};
    const int pout_v[1] = {1};
    Camkes_config::initialize_ports(&print0,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&print0,true,0,&discard,0);
   
    Print print1;
    Vector<String> print_config1;
    print_config1.push_back("port1");
    re = Camkes_config::set_nports(&print1,1,1);
    debugging("setting n ports for print1",re);
    re = print1.configure(print_config1,&feh);
    debugging("finishing configuration for print",re);
    Camkes_config::initialize_ports(&print1,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&print1,true,0,&discard,0);

    Print print2;
    Vector<String> print_config2;
    print_config2.push_back("port2");
    re = Camkes_config::set_nports(&print2,1,1);
    debugging("setting n ports for print2",re);
    re = print2.configure(print_config2,&feh);
    debugging("finishing configuration for print",re);
    Camkes_config::initialize_ports(&print2,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&print2,true,0,&discard,0);

    Print print3;
    Vector<String> print_config3;
    print_config3.push_back("port3");
    re = Camkes_config::set_nports(&print3,1,1);
    debugging("setting n ports for print3",re);
    re = print3.configure(print_config3,&feh);
    debugging("finishing configuration for print",re);
    Camkes_config::initialize_ports(&print3,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&print3,true,0,&discard,0);


    //Try creating a classifer 
    //For etherType infomration look at here https://en.wikipedia.org/wiki/EtherType
    Classifier clsf;
    Vector<String> clsf_config;//At the moment hard code a vector to configure it
    clsf_config.push_back("12/0806 20/0001");
    clsf_config.push_back("12/0806 20/0002");
    clsf_config.push_back("12/0800");
    clsf_config.push_back("-"); 
    
    re = Camkes_config::set_nports(&clsf,1,4);
    debugging("setting n ports for classifier",re);
    re = clsf.configure(clsf_config,&feh);
    debugging("finish configuration for classifier",re);
    const int clsf_in_v[1] = {1};//0:Bidirectional 1:push 2:pull
    const int clsf_out_v[4] = {1,1,1,1};
    Camkes_config::initialize_ports(&clsf,clsf_in_v,clsf_out_v); //one input three output
    Camkes_config::connect_port(&clsf,true,0,&print0,0);//true int Elment int
    Camkes_config::connect_port(&clsf,true,1,&print1,0);
    Camkes_config::connect_port(&clsf,true,2,&print2,0);
    Camkes_config::connect_port(&clsf,true,3,&print3,0); 




    //open pccap
    descr = pcap_open_live(device,BUFSIZ,1,-1,errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }


    pcap_loop(descr, -1, my_packet_handler, (u_char*)&clsf);
            

    return 0;
}
