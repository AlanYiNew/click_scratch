#pragma once
#include <buffer.h>
#define RT_NUM_ENTRY 4
#define NUM_COMPONENT 2
typedef struct message{
   int ready;
   char content[PACKET_BUFSIZE-sizeof(int)];//4:the size of ready
}  message_t;

typedef void (*eventfunc_t)();

