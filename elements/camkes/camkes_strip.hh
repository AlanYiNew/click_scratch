// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_STRIP_HH
#define CLICK_STRIP_HH
#include <click/element.hh>
#include <porttype.h>
CLICK_DECLS

/*
 * =c
 * Strip(LENGTH)
 * =s basicmod
 * strips bytes from front of packets
 * =d
 * Deletes the first LENGTH bytes from each packet.
 * =e
 * Use this to get rid of the Ethernet header:
 *
 *   Strip(14)
 * =a StripToNetworkHeader, StripIPHeader, EtherEncap, IPEncap, Truncate
 */

class Camkes_Strip : public Element { public:

    Camkes_Strip() CLICK_COLD;

    message_t *_camkes_buf;
    eventfunc_t  _ev_emit; 
    const char *class_name() const		{ return "Camkes Strip"; }
    const char *port_count() const		{ return PORTS_1_1; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    void push(int, Packet*);
    Packet *simple_action(Packet *);

  private:

    unsigned _nbytes;

};

CLICK_ENDDECLS
#endif
