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
#include <click/element.hh>
#include <click/error.hh>
#include "elements/camkes/camkes_classifier.hh"
#include "elements/standard/print.hh"
#include "elements/ethernet/arpresponder.hh"
#include "elements/userlevel/fromdevice.hh"
#include "elements/standard/discard.hh"
#include "elements/userlevel/todevice.hh"
#include "elements/standard/simplequeue.hh"
#include "elements/camkes/camkes_paint.hh"
#include <iostream>
#include <iomanip>
#include "elements/standard/dropbroadcasts.hh"
#include "elements/standard/painttee.hh"
#include "elements/camkes/camkes_icmperror.hh"
#include "elements/ip/ipgwoptions.hh"
#include "elements/ip/fixipsrc.hh"
#include "elements/ip/ipnameinfo.hh"
#include "elements/ip/decipttl.hh"
#include "elements/ip/ipfragmenter.hh"
#include <click/nameinfo.hh>
#include "elements/ethernet/arpquerier.hh"

/* XXX: CAmkES symbols that are linked in after this file is compiled.
   They need to be marked as weak and this is the current hacky way it is done */
extern "C" {
    void *camkes_buffer;
    void ev2routing_emit(void); 
    void ev_wait(void);
    void *aq_sendbuffer;
    void *aq_recvbuffer;
    const char * wm_val;
    void *db_buffer;
    void *icmp_buffer;
    const char * camkes_id_attributes;
    const char * ip_addr;
    const char * mac;
    const char * proxy_arp[NUM_COMPONENT-1];
    void ev2aq_emit(void);
}

#pragma weak wm_val
#pragma weak camkes_buffer
#pragma weak ev2routing_emit
#pragma weak ev_wait
#pragma weak strip_push_port
#pragma weak db_buffer
#pragma weak camkes_id_attributes
#pragma weak ip_addr
#pragma weak mac
#pragma weak icmp_buffer
#pragma weak proxy_arp
#pragma weak aq_sendbuffer
#pragma weak aq_recvbuffer
#pragma weak ev2aq_emit

extern void click_export_elements();

const int pin_v[1] = {1};//input direction
const int pout_v[1] = {1};//output direction

const int pin_v2[2] = {1,1};
const int pout_v2[2] = {1,1};
void setup_paintTee(PaintTee& paintTee,FileErrorHandler &feh );
void setup_cicmprd(Camkes_ICMPError& icmprd,FileErrorHandler &feh );
void setup_ipgwoptions(IPGWOptions & ipgwoptions,FileErrorHandler &feh);
void setup_arpRes(ARPResponder &arpRes,FileErrorHandler &feh);
void setup_cclsf(Camkes_Classifier &clsf,FileErrorHandler &feh);
void setup_tDev(ToDevice & tDev,FromDevice & fDev, FileErrorHandler & feh);
void setup_fDev(FromDevice & fDev, FileErrorHandler & feh);
void setup_cpaint(Camkes_Paint& cpaint,FileErrorHandler & feh);
void setup_queue(SimpleQueue& queue,FileErrorHandler &feh);
void setup_cicmpbp(Camkes_ICMPError& icmpbp,FileErrorHandler &feh );
void setup_fips(FixIPSrc& fips,FileErrorHandler &feh);
void setup_dipttl(DecIPTTL &dipttl, FileErrorHandler &feh);
void setup_cicmpttl(Camkes_ICMPError& icmpttl,FileErrorHandler &feh );
void setup_ipf(IPFragmenter& ipf,FileErrorHandler &feh );
void setup_cicmpmf(Camkes_ICMPError& icmpmf,FileErrorHandler &feh );
void setup_arpQue(ARPQuerier& arpQue,FileErrorHandler &feh );
void setup_db(DropBroadcasts& db, FileErrorHandler &feh);
void inline debugging(const char* s,int val){
     std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}


int main (int argc, char *argv[]) {

    message_t * buffer_str = (message_t*)camkes_buffer;


    //snprintf(buffer_str->content, PACKET_MAX_LEN, "Hello, World!");
    //printf("Sending string: %s\n", buffer_str->content);
    /* Signal the string reverse server and wait for response */
    //buffer_str->ready = 1;
    //camkes_ev_emit();

    //camkes_ev1_wait();

    //printf("%s\n", buffer_str);

    char errbuf[PCAP_ERRBUF_SIZE]; 

    pcap_t* descr;
//#####################################################################
#if CAMKES_DEBUG
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
#endif
    //####################################################################
    // Click relervant code

    //Discard packets
    Discard discard;
    //Todevice
    ToDevice tDev;
    //Arp element
    ARPResponder arpRes;
    //Classifier
    Camkes_Classifier cclsf;
    //FromDevice
    FromDevice fDev;
    //Fullnotequeue
    SimpleQueue queue;
    //paint element used for icmp
    Camkes_Paint cpaint;
    //print 0
    Print print0;
    //print 1
    Print print1;
    //print 2
    Print print2;
    //print 3 
    Print print3;
    //DropBroadCasts
    DropBroadcasts db;
    //CheckPaint
    PaintTee paintTee;
    //ICMPError redirect
    Camkes_ICMPError cicmprd;
    //ICMPError parameter problem
    Camkes_ICMPError cicmpbp;
    //ICMPError ttl 
    Camkes_ICMPError cicmpttl;
    //ICMPError must flag 
    Camkes_ICMPError cicmpmf; 
    //IPGWOptions
    IPGWOptions ipgwoptions;
    //IPFixSrc
    FixIPSrc fips;
    //DecIPTTL
    DecIPTTL dipttl;
    //IPFragmenter
    IPFragmenter ipf;
    //ARPQuerier
    ARPQuerier arpQue;

    int re = 0;

    NameInfo::static_initialize();
    IPNameInfo::static_initialize();


    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");
    IPNameInfo::static_initialize(); 

    //setup arpQue
    setup_arpQue(arpQue,feh);
    Camkes_config::connect_port(&arpQue,true,0,&queue,0);

    //setup ipf
    setup_ipf(ipf,feh);
    Camkes_config::connect_port(&ipf,true,0,&arpQue,0);
    Camkes_config::connect_port(&ipf,true,1,&cicmpmf,0);

    //setup dipttl
    setup_dipttl(dipttl,feh);
    Camkes_config::connect_port(&dipttl,true,0,&ipf,0);
    Camkes_config::connect_port(&dipttl,true,1,&cicmpttl,0);

    //setuo fips
    setup_fips(fips,feh);
    Camkes_config::connect_port(&fips,true,0,&dipttl,0);

    //setup ipgwoptions
    setup_ipgwoptions(ipgwoptions,feh);
    Camkes_config::connect_port(&ipgwoptions,true,0,&fips,0);
    Camkes_config::connect_port(&ipgwoptions,true,1,&cicmpbp,0);

    //Configuring icmpttl
    setup_cicmpmf(cicmpmf,feh);

    //Configuring icmpttl
    setup_cicmpttl(cicmpttl,feh);

    //Configuring icmprd
    setup_cicmprd(cicmprd,feh);
    //Camkes_config::connect_port(&cicmprd,true,0,&print0,0);

    //Configuring icmp badparameter
    setup_cicmpbp(cicmpbp,feh);

    //Configuring checkpaint
    setup_paintTee(paintTee,feh); 
    Camkes_config::connect_port(&paintTee,true,0,&ipgwoptions,0);
    Camkes_config::connect_port(&paintTee,true,1,&cicmprd,0);

    //No configuration for dropbroadcast but just connect it
    setup_db(db,feh);
    Camkes_config::connect_port(&db,true,0,&paintTee,0);


    //Configuring discard
    re = Camkes_config::set_nports(&discard,1,0);
    debugging("setting n ports for discard",re);
    Camkes_config::initialize_ports(&discard,pin_v,NULL);//We don't have output port putting in_v is fine
    debugging("No configuration call to discard",0);    

    //Configuring cpaint
    setup_cpaint(cpaint,feh); 

    //Configuring arp element
    setup_arpRes(arpRes,feh);  
    Camkes_config::connect_port(&arpRes,true,0,&queue,0);//true int Elment int

    //Configuring classifer 
    setup_cclsf(cclsf,feh);
    Camkes_config::connect_port(&cclsf,true,0,&arpRes,0);//true int Elment int
    //Camkes_config::connect_port(&cclsf,true,1,&arpQue,1);
    Camkes_config::connect_port(&cclsf,true,2,&cpaint,0);
    Camkes_config::connect_port(&cclsf,true,3,&discard,0);//other packet 

    //Configuring fromDevice
    setup_fDev(fDev,feh); 
    Camkes_config::connect_port(&fDev,true,0,&cclsf,0);

    //Configuring toDevice 
    setup_tDev(tDev,fDev,feh);
    Camkes_config::connect_port(&tDev,false,0,&queue,0);    

    //Configuring queue 
    setup_queue(queue,feh); 

    Camkes_proxy cp[2] = {{&db,(message_t*)db_buffer},
                          {&arpQue,(message_t*)aq_recvbuffer,1}};    
    Camkes_config::start_pcap_dispatch(&fDev,&tDev,cp,2,NULL);

    return 0;

}

void setup_cicmpbp(Camkes_ICMPError& icmpbp,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmpbp_config;
    icmpbp_config.push_back(ip_addr);
    icmpbp_config.push_back("parameterproblem");
    re = Camkes_config::set_nports(&icmpbp,1,1);        
    debugging("setting n ports for icmpbp",re);
    re = icmpbp.configure(icmpbp_config,&feh);
    debugging("finishing configuration for icmpbp",re);
    Camkes_config::initialize_ports(&icmpbp,pin_v,pout_v);

    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmpbp.setup_proxy(buffer,ev,1);

}

void setup_cicmprd(Camkes_ICMPError& icmprd,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmprd_config;
    icmprd_config.push_back(ip_addr);
    icmprd_config.push_back("redirect");
    icmprd_config.push_back("host");
    re = Camkes_config::set_nports(&icmprd,1,1);        
    debugging("setting n ports for icmprd",re);
    re = icmprd.configure(icmprd_config,&feh);
    debugging("finishing configuration for icmprd",re);
    Camkes_config::initialize_ports(&icmprd,pin_v,pout_v);
    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmprd.setup_proxy(buffer,ev,1);
}

void setup_cicmpttl(Camkes_ICMPError& icmpttl,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmpttl_config;
    icmpttl_config.push_back(ip_addr);
    icmpttl_config.push_back("timeexceeded");
    re = Camkes_config::set_nports(&icmpttl,1,1);        
    debugging("setting n ports for icmpttl",re);
    re = icmpttl.configure(icmpttl_config,&feh);
    debugging("finishing configuration for icmpttl",re);
    Camkes_config::initialize_ports(&icmpttl,pin_v,pout_v);
    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmpttl.setup_proxy(buffer,ev,1);

}

void setup_cicmpmf(Camkes_ICMPError& icmpmf,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmpmf_config;
    icmpmf_config.push_back(ip_addr);
    icmpmf_config.push_back("unreachable");
    icmpmf_config.push_back("needfrag");
    re = Camkes_config::set_nports(&icmpmf,1,1);        
    debugging("setting n ports for icmpmf",re);
    re = icmpmf.configure(icmpmf_config,&feh);
    debugging("finishing configuration for icmpmf",re);
    Camkes_config::initialize_ports(&icmpmf,pin_v,pout_v);
    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmpmf.setup_proxy(buffer,ev,1);

}

void setup_paintTee(PaintTee& paintTee,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> paintTee_config;
    paintTee_config.push_back(String("COLOR ") + String(camkes_id_attributes));
    debugging("setting n ports for paintTee",re);
    re = Camkes_config::set_nports(&paintTee,1,2);       
    re = paintTee.configure(paintTee_config,&feh);
    debugging("finishing configuration for paintTee",re);
    Camkes_config::initialize_ports(&paintTee,pin_v,pout_v2);

}

void setup_ipgwoptions(IPGWOptions & ipgwoptions,FileErrorHandler &feh){
    int re = 0;
    Vector<String> ipgwoptions_config;
    ipgwoptions_config.push_back(String(ip_addr));
    debugging("setting n ports for ipgoptions",re);
    re = Camkes_config::set_nports(&ipgwoptions,1,1);       
    re = ipgwoptions.configure(ipgwoptions_config,&feh);
    debugging("finishing configuration for ipgwoptions",re);
    Camkes_config::initialize_ports(&ipgwoptions,pin_v,pout_v);
}

void setup_arpRes(ARPResponder &arpRes,FileErrorHandler &feh){
    Vector<String> arpRes_config;
    arpRes_config.push_back(String(ip_addr) + String(" ") + String(mac));
    for (int i = 0; i < NUM_COMPONENT-1; i++){
        arpRes_config.push_back(proxy_arp[i]);
    }

    int re = Camkes_config::set_nports(&arpRes,1,1); 
    debugging("setting n ports for arpResponder",re);
    re = arpRes.configure(arpRes_config,&feh); 
    debugging("finish configuration for arpResponder",re);
    const int arpRes_in_v[1] = {1};//0:Bidirectional 1:push 2:pull
    const int arpRes_out_v[1] = {1};
    Camkes_config::initialize_ports(&arpRes,arpRes_in_v,arpRes_out_v); //one input three output
}

void setup_cclsf(Camkes_Classifier &clsf,FileErrorHandler &feh){
    //For etherType infomration look at here https://en.wikipedia.org/wiki/EtherType
    Vector<String> clsf_config;//At the moment hard code a vector to configure it
    clsf_config.push_back("12/0806 20/0001");
    clsf_config.push_back("12/0806 20/0002");
    clsf_config.push_back("12/0800");
    clsf_config.push_back("-");  
    int re = Camkes_config::set_nports(&clsf,1,4);
    debugging("setting n ports for classifier",re);
    re = clsf.configure(clsf_config,&feh);
    debugging("finish configuration for classifier",re);
    const int clsf_in_v[1] = {1};//0:Bidirectional 1:push 2:pull
    const int clsf_out_v[4] = {1,1,1,1};
    Camkes_config::initialize_ports(&clsf,clsf_in_v,clsf_out_v); //one input four output
    message_t* buffer[4] = {NULL,(message_t*)aq_recvbuffer,NULL,NULL};
    eventfunc_t event[4] = {NULL,ev2aq_emit,NULL,NULL};
    clsf.setup_proxy(buffer,event,4);
}

void setup_tDev(ToDevice & tDev,FromDevice & fDev, FileErrorHandler & feh){
    Vector<String> tDev_config;
    tDev_config.push_back((char *)wm_val);
    int re = Camkes_config::set_nports(&tDev,1,0);
    debugging("setting n ports for tDev",re);
    re = tDev.configure(tDev_config,&feh,&fDev);
    debugging("finishing configuration for tDev",re);
    const int tDev_in_v[1] = {2};
    Camkes_config::initialize_ports(&tDev,tDev_in_v,NULL); //one input no output
    debugging("attempting to initialize tDev",re);
    Camkes_config::initialize(&tDev,&feh);
}

void setup_fDev(FromDevice & fDev, FileErrorHandler & feh){
    Vector<String> fDev_config;
    fDev_config.push_back((char *)wm_val);
    fDev_config.push_back("PROMISC true");
    int re = Camkes_config::set_nports(&fDev,1,1);
    debugging("setting n ports for fDev",re);
    re = fDev.configure(fDev_config,&feh);
    debugging("finishing configuration for fDev",re);
    Camkes_config::initialize_ports(&fDev,pin_v,pout_v); //one input one output
    debugging("attempting to initialize fDev",re);
    Camkes_config::initialize(&fDev,&feh);
}

void setup_cpaint(Camkes_Paint& cpaint,FileErrorHandler & feh){
    Vector<String> cpaint_config;
    cpaint_config.push_back(String("COLOR ") + String(camkes_id_attributes));
    int re = Camkes_config::set_nports(&cpaint,1,1);
    debugging("setting n ports for paint",re);
    re = cpaint.configure(cpaint_config,&feh);
    debugging("finishing configuration for paint",re);
    Camkes_config::initialize_ports(&cpaint,pin_v,pout_v); //one input one output
    message_t* buffer[1] = {(message_t*)camkes_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    cpaint.setup_proxy(buffer,ev,1);
}

void setup_queue(SimpleQueue& queue,FileErrorHandler &feh){
    Vector<String> queue_config;
    queue_config.push_back("6000");
    int re = Camkes_config::set_nports(&queue,1,1);
    debugging("setting n ports for queue",re);
    re = queue.configure(queue_config,&feh);
    debugging("finishing configuration for queue",re);
    const int queue_in_v[1] = {1};//0:Bidirectional 1:push 2:pull
    const int queue_out_v[1] = {2};
    Camkes_config::initialize_ports(&queue,queue_in_v,queue_out_v); //one input one output 
    debugging("attempting to initialize queue",re);
    Camkes_config::initialize(&queue,&feh);
}

void setup_fips(FixIPSrc& fips,FileErrorHandler &feh){
    Vector<String> fips_config;
    fips_config.push_back(ip_addr);
    int re = Camkes_config::set_nports(&fips,1,1);
    debugging("setting n ports for fips",re);
    re = fips.configure(fips_config,&feh);
    debugging("finishing configuration for fips",re);
    Camkes_config::initialize_ports(&fips,pin_v,pout_v); //one input one output 
    debugging("attempting to initialize fips",re);
    Camkes_config::initialize(&fips,&feh);
}

void setup_dipttl(DecIPTTL &dipttl, FileErrorHandler &feh){
    int re = Camkes_config::set_nports(&dipttl,1,2);
    debugging("setting n ports for dipttl",re);
    debugging("no configuration for dipttl",re);
    Camkes_config::initialize_ports(&dipttl,pin_v,pout_v2); //one input one output 
    debugging("attempting to initialize dipttl",re);
    Camkes_config::initialize(&dipttl,&feh);
}

void setup_ipf(IPFragmenter& ipf,FileErrorHandler &feh ){
    Vector<String> ipf_config;
    ipf_config.push_back("1500");//TODO make it flexible
    int re = Camkes_config::set_nports(&ipf,1,1); 
    debugging("setting n ports for ipf",re);
    re = ipf.configure(ipf_config,&feh); 
    debugging("finish configuration for ipf",re);
    Camkes_config::initialize_ports(&ipf,pin_v,pout_v); //one input three output
}

void setup_arpQue(ARPQuerier& arpQue,FileErrorHandler &feh ){
    Vector<String> arpQue_config;
    arpQue_config.push_back(ip_addr);
    arpQue_config.push_back(mac);
    int re = Camkes_config::set_nports(&arpQue,2,1); 
    debugging("setting n ports for arpQue",re);
    re = arpQue.configure(arpQue_config,&feh); 
    debugging("finish configuration for arpQue",re);
    Camkes_config::initialize_ports(&arpQue,pin_v2,pout_v); //one input three output
}

void setup_db(DropBroadcasts& db, FileErrorHandler &feh){
    int re = Camkes_config::set_nports(&db,1,1); 
    debugging("setting n ports for db",re);
    Camkes_config::initialize_ports(&db,pin_v,pout_v); //one input three output
}
