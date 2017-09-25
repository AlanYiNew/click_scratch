#include <click/element.hh>
#include <click/handler.hh>
#include <iostream>
#include <click/packet.hh>
#include <clicknet/ip.h>
#include "porttype.h"
#include <click/camkes_config.hh>
class Camkes_config{
    public:
        static int connect_port(Element* tar,bool isoutput, int port, Element* e, int e_port);

        static void initialize_ports(Element* tar,const int* input_codes, const int* output_codes);

        static int set_nports(Element* tar,int ninputs,int noutputs);

        static void initialize(Element* tar, ErrorHandler * eh);

        static void start_pcap_dispatch(Element* recv,Element* send,Camkes_proxy * cp,int num);

        //Mashalling
        static int packet_serialize(Packet * dst,Packet *src);

        //vtable realted. Be careful.Demarshalling 
        static void deserialize_packet(Packet* &dst,void* src);

        static void recycle(Packet * p);

        void Camkes_config::start_proxy(Camkes_proxy_m *cp,int num);
};

class Camkes_proxy{
    private:
    Element * elem;
    message_t * buffer;
    public:
        Camkes_proxy(Element * elemm, message_t * bufferr):elem(elemm),buffer(bufferr){};
        void push();
};

class Camkes_proxy_m{
    private:
    Element * elem;
    using buf_func_t =  message_t * (*func)(int);
    buf_func_t func;
       public:
        Camkes_proxy(Element * elemm, buf_func_t func):elem(elemm),buffer(bufferr){};
        void push();
};
