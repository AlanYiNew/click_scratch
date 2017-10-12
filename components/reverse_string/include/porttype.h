#pragma once
#include <buffer.h>
typedef struct message{
   int ready;
   char content[PACKET_BUFSIZE/2-4];//4:the size of ready
   int ready2;
   char content2[PACKET_BUFSIZE/2-4];
}  message_t;

typedef void (*eventfunc_t)();
