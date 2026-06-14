/*
 * randombytes.c - the CSPRNG that TweetNaCl requires the application to supply.
 *
 * Reads from the OS entropy source. On Linux this is getrandom(2) with a
 * /dev/urandom fallback; on other POSIX hosts (e.g. macOS for the self-test)
 * it falls back to /dev/urandom directly.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

void randombytes(unsigned char *x, unsigned long long xlen);

void randombytes(unsigned char *x, unsigned long long xlen)
{
    size_t off = 0;

#if defined(__linux__)
    while (off < xlen) {
        ssize_t r = getrandom(x + off, (size_t)(xlen - off), 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break; /* fall through to /dev/urandom */
        }
        off += (size_t)r;
    }
    if (off == xlen)
        return;
#endif

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "FATAL: cannot open /dev/urandom for entropy\n");
        abort();
    }
    while (off < xlen) {
        ssize_t r = read(fd, x + off, (size_t)(xlen - off));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "FATAL: /dev/urandom read failed\n");
            abort();
        }
        off += (size_t)r;
    }
    close(fd);
}
