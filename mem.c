#include "mem.h"
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int is_readable_mem (const void *ptr, size_t nbytes)
{
    static int fd = open (".", O_TMPFILE | O_WRONLY);

    errno = 0;
    write (fd, ptr, nbytes); 

    return (errno == EFAULT) ? 0 : 1;
}
