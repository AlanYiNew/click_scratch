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

#include <camkes.h>
#include <buffer.h>
#include <string.h>
#include <stdio.h>
//2 client component at the moment
#include <porttype.h>
#define NUM_COMPONENT 2

message_t *section[NUM_COMPONENT];
emitfun_t ev_func[NUM_COMPONENT];

int run(void) {
    
    int c = 0;
    while(true) {
        /* Wait for event */
        ev_wait();

        char *buffer_str;
        for (c = 0;c < NUM_COMPONENT && !((message_t *)buffer_buf(c))->ready; c++);
        
            
        buffer_str = ((message_t *)buffer_buf(c))->content;

        printf("Got string: %s from \n", buffer_str);

        int len = strnlen(buffer_str, REVERSE_STRING_MAX_LEN);
        for (int i = 0; i < len / 2; ++i) {
            int swap_idx = len - i - 1;
            char tmp = buffer_str[i];
            buffer_str[i] = buffer_str[swap_idx];
            buffer_str[swap_idx] = tmp;
        }

        /* Signal to client that we are finished */
        ev_func[c](); 

        ((message_t *)buffer_buf(0))->ready=0;
    }

    return 0;
}

void pre_init(){
    //too lazy to write a template to generalise this, so use pre_init to hack this portion
    //section[0] = (message_t*)buffer0;
    //section[1] = (message_t*)buffer1;

    ev_func[0] = ev1_emit;
    ev_func[1] = ev2_emit;
}
