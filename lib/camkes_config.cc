#include <click/config.h>
#include <click/element.hh>
#include <click/handler.hh>
#include <iostream>
#include <click/packet.hh>
#include <clicknet/ip.h>
#include "porttype.h"
#include <click/camkes_config.hh>

int Camkes_config::connect_port(Element* tar,bool isoutput, int port, Element* e, int e_port){
    return tar->connect_port(isoutput,port,e,e_port);
}

void Camkes_config::initialize_ports(Element* tar,const int* input_codes, const int* output_codes){
    tar->initialize_ports(input_codes,output_codes);
}

int Camkes_config::set_nports(Element* tar,int ninputs,int noutputs){
    return tar->set_nports(ninputs,noutputs);
}

void Camkes_config::initialize(Element* tar, ErrorHandler * eh){
    tar->initialize(eh);
}

void Camkes_config::start_pcap_dispatch(Element* recv,Element* send,Camkes_proxy * cp,int num){
    while (true){
        for (int i = 0 ; i < num ;i++)
            cp[i].push();
        recv->selected(0,0);
        send->run_task(NULL);
    }
}

//Mashalling
int Camkes_config::packet_serialize(Packet * dst,Packet *src){
    /*debugging purpose */
    unsigned char *ipchar = (unsigned char *)(src->data()+30); 
    for (int i = 0 ; i < 4 ;++i){
        std::cout << (int)ipchar[i];
        if (i < 3)
            std::cout << ".";
    }
    std::cout << std::endl;

    memcpy(dst,src,sizeof(Packet)); 
    dst->_head = reinterpret_cast<unsigned char*>(dst) + sizeof(Packet);
    //I made the shared memory buffer the size of 4096 - sizeof(int) - sizeof(Packet). It should still be far greater than any buffer_length() whose max value normally may just be 2048
    dst->_end = reinterpret_cast<unsigned char*>(dst) +  src->buffer_length();
    if (src->headroom() + src->length() > dst->buffer_length())
        return false;
    dst->_data = dst->_head + src->headroom();
    memcpy(dst->_data,src->data(),src->length());

    dst->_tail = dst->_data + src->length();
    dst->copy_annotations(src);
    if (src->mac_header())
        dst->set_mac_header(dst->data() + src->mac_header_offset() ); 
    if (src->network_header())
        dst->set_network_header(dst->data() + src->network_header_offset(), src->network_header_length()); 

    ipchar = ((unsigned char *)dst->data())+30; 
    std::cout << "ip inside sender shared mem";
    for (int i = 0 ; i < 4 ;++i){
        std::cout << (int)ipchar[i];
        if (i < 3)
            std::cout << ".";
    }
    std::cout << std::endl; 
}



//vtable realted. Be careful.Demarshalling 
void Camkes_config::deserialize_packet(Packet* &dst,void* src){
    Packet * p = reinterpret_cast<Packet*>(src);  



    int headroom = p->headroom();
    int length = p->length();
    int nh_offset = p->network_header_offset();
    int mac_offset = p->mac_header_offset();
    int nh_length = p->network_header_length();
    int buffer_length = p->buffer_length();

    p->_head = reinterpret_cast<unsigned char*>(src) + sizeof(Packet);
    p->_end = p->_head + buffer_length;
    p->_data = p->_head + headroom;
    p->_tail = p->_data+ length; 

    dst = Packet::make(p->headroom(),p->data(),p->length(),p->tailroom()); 
    dst->copy_annotations(p); 
    if (p->mac_header())
        dst->set_mac_header(dst->data() + mac_offset ); 
    if (p->network_header())
        dst->set_network_header(dst->data() + nh_offset, nh_length);

    unsigned char *ipchar = ((unsigned char *)dst->data())+30; 
    std::cout << "ip after deserialization";
    for (int i = 0 ; i < 4 ;++i){
        std::cout << (int)ipchar[i];
        if (i < 3)
            std::cout << ".";
    }
    std::cout << std::endl;
}

void Camkes_config::recycle(Packet * p){
    delete p;
}

Camkes_proxy::Camkes_proxy(Element * elemm, message_t * bufferr):elem(elemm),buffer(bufferr){}
void Camkes_proxy::push(){
    if (buffer->ready){
        Packet * p;
        Camkes_config::deserialize_packet(p,(void*)(&(buffer->content)));
        buffer->ready = 0;
        elem->push(0,p);
    }
}


