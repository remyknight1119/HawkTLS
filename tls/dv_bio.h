#ifndef __DV_BIO_H__
#define __DV_BIO_H__

extern int dv_bio_read_sock(int fd, void *buf, dv_u32 len);
extern int dv_bio_write_sock(int fd, const void *buf, dv_u32 len);
extern int dv_bio_get_time_linux(dv_u32 *t);
extern int dv_bio_read_file_linux(const char *file, void **data);

#endif
