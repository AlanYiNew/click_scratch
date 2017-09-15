/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#include <buffer.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
//2 client component at the moment
#include <porttype.h>
#include <click/packet.hh>
#define NUM_COMPONENT 2

//Click related include
#include "elements/ip/checkipheader.hh"
#include <click/camkes_config.hh>
#include <click/config.h>
#include <click/element.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include "elements/standard/print.hh"
#include "elements/standard/discard.hh"
#include "elements/standard/strip.hh"
#include "elements/ip/getipaddress.hh"
#include "elements/ip/lookupiproute.hh"

extern "C" {
    //message_t *section[NUM_COMPONENT];
    eventfunc_t ev_func[NUM_COMPONENT];
    void ev_wait(void);
    void* buffer_buf(int); 
    void ev1_emit(void);
    void ev2_emit(void);
//    const char *ip_addr0;
    const char *ip_addr1;
//    const char *ip_addr2;
    void ** rt;
}

#pragma weak ev1_emit
#pragma weak ev2_emit
#pragma weak buffer_buf
#pragma weak ev_wait
#pragma weak ip_addr1
#pragma weak rt;

void inline debugging(const char* s,int val){
    std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}

int main(int argc, char *argv[]) {
    /* Click configuration */
    int re = 0;
    
    //Shared pin,pout
    const int pin_v[1] = {1};//0:Bidirectional 1:push 2:pull
    const int pout_v[1] = {1};
    
    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    //proxy strip
    Strip strip;
    //ChceckIPHeader    
    CheckIPHeader cih;
    //Print element
    Print print;
    //Discard element
    Discard discard;
    //GetIPAddress
    GetIPAddress gia;
    //LookIPRoute
    StaticIPLookup lir;

    //Configuring StaticIPRoute
    Vector<String> lir_config;
    lir_config.push_back("16");
    re = Camkes_config::set_nports(&lir,1,1); 
    debugging("setting n ports for lir",re);
    re = strip.configure(lir_config,&feh); 
    debugging("finish configuration for lir",re);
    Camkes_config::initialize_ports(&lir,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&lir,true,0,&print,0);//true int Element int
    
    //Configuring GetIPAddres
    Vector<String> gia_config;
    gia_config.push_back("16");
    re = Camkes_config::set_nports(&gia,1,1); 
    debugging("setting n ports for gia",re);
    re = strip.configure(gia_config,&feh); 
    debugging("finish configuration for gia",re);
    Camkes_config::initialize_ports(&gia,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&gia,true,0,&lir,0);//true int Element int

    //Configuring cameks strip
    Vector<String> strip_config;
    strip_config.push_back("LENGTH 14");
    re = Camkes_config::set_nports(&strip,1,1); 
    debugging("setting n ports for strip",re);
    re = strip.configure(strip_config,&feh); 
    debugging("finish configuration for strip",re);
    Camkes_config::initialize_ports(&strip,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&strip,true,0,&cih,0);//true int Element int

    //Configuring cih
    Vector<String> cih_config;//At the moment hard code a vector to configure it
    cih_config.push_back(String("INTERFACES ") + ip_addr1);
    re = Camkes_config::set_nports(&cih,1,1);
    debugging("setting n ports for cih",re);
    re = cih.configure(cih_config,&feh);
    debugging("finish configuration for cih",re);
    Camkes_config::initialize_ports(&cih,pin_v,pout_v); //one input one output
    Camkes_config::connect_port(&cih,true,0,&gia,0);//true int Element int
    
    //Configuring print mainly for debgugging purpose
    Vector<String> print_config;
    print_config.push_back("ok");
    re = Camkes_config::set_nports(&print,1,1);
    debugging("setting n ports for print",re);
    re = print.configure(print_config,&feh);
    debugging("finishing configuration for print",re); 
    Camkes_config::initialize_ports(&print,pin_v,pout_v); //one input one output
    Camkes_config::connect_port(&print,true,0,&discard,0);

    //Configuring discard
    re = Camkes_config::set_nports(&discard,1,0);
    debugging("setting n ports for discard",re);
    Camkes_config::initialize_ports(&discard,pin_v,NULL);//We don't have output port putting in_v is fine
    debugging("No configuration call to discard",0); 

    int count = 2;
    int c = 0;
    while(true) {
        /* Wait for event */

        ev_wait();
        
        char *buffer_str;
        for (c = 0;c < NUM_COMPONENT && !((message_t *)buffer_buf(c))->ready; c=(c+1)%NUM_COMPONENT);
          
        std::cout << "unblocked by id:" << c << std::endl; 
        message_t * message  = ((message_t *)buffer_buf(c));

        if (count-- > 0) {
            buffer_str = (char*)&(message->content); 
            int len = strnlen(buffer_str, PACKET_MAX_LEN);
            for (int i = 0; i < len / 2; ++i) {
                int swap_idx = len - i - 1;
                char tmp = buffer_str[i];
                buffer_str[i] = buffer_str[swap_idx];
                buffer_str[swap_idx] = tmp;
            }
            printf("result strng:%s\n",buffer_str);
        }   else {
            Packet *p; 
            //TODO This line will potential cause memory leak, no time to check at the moment
            Camkes_config::deserialize_packet(p,(void*)(&(message->content)));
            printf("%s\n",message->content); 
            printf("Pcaket length %d\n",p->length());
      
            const click_ip *ip = reinterpret_cast<const click_ip *>(p->data() + 14);

            std::cout << "ip->v:" << ip->ip_v << std::endl;
            strip.push(0,p); 

        }
        
        /* Signal to client that we are finished */
        ev_func[c](); 
        
        ((message_t *)buffer_buf(c))->ready=0;
        
        //It's dynamically acllocated in camkes_config
        //Not a good design but haven't found en effective way to do this 
        //Camkes_config::recycle(p);
    }

    return 0;
}

extern "C"{
    void pre_init(){
        //too lazy to write a template to generalise this, so use pre_init to hack this portion
        //section[0] = (message_t*)buffer0;
        //section[1] = (message_t*)buffer1;

        ev_func[0] = ev1_emit;
        ev_func[1] = ev2_emit;
    }
}
