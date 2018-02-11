#ifndef __FC_BUFFER_H__
#define __FC_BUFFER_H__

#define FC_BUF_MEM_FLAG_SECURE      0x01

extern FC_BUF_MEM *FC_BUF_MEM_new_ex(unsigned long flags);
extern FC_BUF_MEM *FC_BUF_MEM_new(void);
extern void FC_BUF_MEM_free(FC_BUF_MEM *a);
extern size_t FC_BUF_MEM_grow(FC_BUF_MEM *str, size_t len);
extern size_t FC_BUF_MEM_grow_clean(FC_BUF_MEM *str, size_t len);

#endif
