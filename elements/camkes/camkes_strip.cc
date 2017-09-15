// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * strip.{cc,hh} -- element strips bytes from front of packet
 * Robert Morris, Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "camkes_strip.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <iostream>
#include <clicknet/ip.h>
CLICK_DECLS

Camkes_Strip::Camkes_Strip()
{
}

int
Camkes_Strip::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
           .read_mp("LENGTH", _nbytes)
           .read_mp("CAMKES_BUF",(unsigned long &)_camkes_buf)
           .read_mp("EVENT_FUNC",(unsigned long &)_ev_emit)
           .complete();
}

void Camkes_Strip::push(int port, Packet *p)
{ 
    std::cout << class_name() <<  " pushing" << std::endl;
    p = simple_action(p);
    
    if (p){
        //camkes proxy
        memcpy(_camkes_buf->content,p->data(),p->length());
        _camkes_buf->len = p->length();
        _camkes_buf->ready = 1;
        _ev_emit(); 
    }
        
}

Packet *
Camkes_Strip::simple_action(Packet *p)
{
    p->pull(_nbytes);
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Strip)
ELEMENT_MT_SAFE(Strip)
