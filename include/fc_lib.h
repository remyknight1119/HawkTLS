#ifndef __FC_LIB_H__
#define __FC_LIB_H__

#include <arpa/inet.h>
#include <string.h>

#define fc_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * fc_container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define fc_container_of(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define FC_ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

#define FC_HTONS(a)     htons(a)
#define FC_HTONL(a)     htonl(a)
#define FC_NTOHS(a)     ntohs(a)
#define FC_NTOHL(a)     ntohl(a)

#define FC_MAX(a, b) (a > b ? a:b)
#define FC_MIN(a, b) (a < b ? a:b)

#define FC_SET_LENGTH(dest, value) \
    do { \
        typeof(value)   n; \
        char            tmp[sizeof(value)]; \
        n = FC_HTONL(value); \
        memcpy(tmp, &n, sizeof(tmp)); \
        memcpy(dest, &tmp[sizeof(tmp) - sizeof(dest)], sizeof(dest)); \
    } while (0)

#define FC_GET_LENGTH(value, length) \
    do { \
        char            tmp[sizeof(value)] = {0}; \
        memcpy(&tmp[sizeof(tmp) - sizeof(length)], length, sizeof(length)); \
        memcpy(&value, tmp, sizeof(tmp)); \
        value = FC_NTOHL(value); \
    } while (0)


#endif
