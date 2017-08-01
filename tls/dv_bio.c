#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dv_errno.h"
#include "dv_types.h"
#include "dv_ssl.h"
#include "dv_lib.h"
#include "dv_debug.h"
#include "dv_crypto.h"

int
dv_bio_read_sock(int fd, void *buf, dv_u32 len)
{
    return read(fd, buf, len);
}

int
dv_bio_write_sock(int fd, const void *buf, dv_u32 len)
{
    return write(fd, buf, len);
}

int
dv_bio_get_time_linux(dv_u32 *t)
{
    *t = time(NULL);
    *t = DV_HTONL(*t);

    return 0;
}

int
dv_bio_read_file_linux(const char *file, void **data)
{
    struct stat     st = {};
    int             fd = 0;
    int             len = 0;
    int             rlen = 0;

    fd = open(file, O_RDONLY);
    if (fd < 0) {
        DV_DEBUG("open %s failed!(%s)\n", file, strerror(errno));
        return DV_ERROR;
    }

    if (fstat(fd, &st) < 0) {
        DV_DEBUG("fstat %s failed!(%s)\n", file, strerror(errno));
        close(fd);
        return DV_ERROR;
    }

    len = st.st_size;

    *data = dv_malloc(len);
    if (*data == NULL) {
        DV_DEBUG("Malloc failed!\n");
        close(fd);
        return DV_ERROR;
    }
    rlen = read(fd, *data, len);
    close(fd);
    if (rlen != len) {
        dv_free(*data);
        *data = NULL;
        DV_DEBUG("Read failed!, rlen = %d(%s)\n", rlen, strerror(errno));
        return DV_ERROR;
    }

    return len;
}
