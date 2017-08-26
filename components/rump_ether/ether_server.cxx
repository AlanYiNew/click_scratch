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



int main (int argc, char *argv[]) {

    message_t * buffer_str = (message_t*)camkes_buffer;
    buffer_str->ready = 1;
    snprintf(buffer_str->content, REVERSE_STRING_MAX_LEN, "Hello, World!");
    printf("Sending string: %s\n", buffer_str->content);
    /* Signal the string reverse server and wait for response */
    camkes_ev_emit();
    camkes_ev1_wait();

    printf("%s\n", buffer_str);

    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */


    
    
    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    Print print;
    Vector<String> print_config;
    print_config.push_back("ok");
    print.configure(print_config,&feh);
    const int in_v[1] = {1};
    Camkes_config::initialize_ports(&print,in_v,in_v); //one input three output
    //Try creating a classifer 
    Classifier clsf;
    
    //At the moment hard code a vector to configure it
    Vector<String> clsf_config;
    clsf_config.push_back("12/0806 20/0001"); 
    clsf_config.push_back("12/0806 20/0002");
    clsf_config.push_back("12/0800");
    clsf_config.push_back("-");
    clsf.configure(clsf_config,&feh);
    const int clsf_in_v[1] = {1};//0:Bidirectional 1:push 2:pull
    const int clsf_out_v[3] = {1,1,1};
    Camkes_config::initialize_ports(&clsf,clsf_in_v,clsf_out_v); //one input three output
    Camkes_config::connect_port(&clsf,true,0,&print,0);//true int Elment int
    Camkes_config::connect_port(&clsf,true,1,&print,0);
    Camkes_config::connect_port(&clsf,true,2,&print,0);
    

    //open pccap
    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }


    /*
     *  grab a packet from descr (yay!)                    
     *  u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h) 
     *  so just pass in the descriptor we got from         
     *  our call to pcap_open_live and an allocated        
     *  struct pcap_pkthdr                                 */

    while (1){ 
        packet = pcap_next(descr,&hdr);

        if(packet == NULL){
            /* dinna work *sob* */
            //printf("Didn't grab packet\n");
        }   else{
            /*  struct pcap_pkthdr {
             *      struct timeval ts;   time stamp 
             *      bpf_u_int32 caplen;  length of portion present 
             *      bpf_u_int32;         lebgth this packet (off wire) 
             *  }
             *                                       */

            const struct sniff_ethernet *ethernet; /* The ethernet header */
            const struct sniff_ip *ip; /* The IP header */

            Packet *p = Packet::make(packet,hdr.len);
            clsf.push(0,p);
            ip = (struct sniff_ip*)(packet+SIZE_ETHERNET);
            printf("Grabbed packet of length %d from %s\n",hdr.len,inet_ntoa(ip->ip_src));
            printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec)); 
            printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

        }
    }

    return 0;
}
