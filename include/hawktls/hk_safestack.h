#ifndef __HK_SAFESTACK_H__
#define __HK_SAFESTACK_H__

#define STACK_OF(type) struct stack_st_##type
#define PREDECLARE_STACK_OF(type) STACK_OF(type);

#endif
