#pragma once
#include <buffer.h>
typedef struct message{
   int ready;
   char content[REVERSE_STRING_BUFSIZE-4];//4:the size of ready
}  message_t;

typedef void (*emitfun_t)();

