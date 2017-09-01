#include <click/element.hh>

class Camkes_config{
    public:
        static inline int connect_port(Element* tar,bool isoutput, int port, Element* e, int e_port){
            return tar->connect_port(isoutput,port,e,e_port);
        }

        static inline void initialize_ports(Element* tar,const int* input_codes, const int* output_codes){
            tar->initialize_ports(input_codes,output_codes);
        }

        static inline int set_nports(Element* tar,int ninputs,int noutputs){
            return tar->set_nports(ninputs,noutputs);
        }
};
