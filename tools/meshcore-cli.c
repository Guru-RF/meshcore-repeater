/*
 * meshcore-cli.c - tiny control client for the repeater's local TCP interface.
 *
 * The repeater (when run as a headless service) exposes the operator CLI on
 * 127.0.0.1:<control_port>. This client sends one command per connection and
 * prints the reply.
 *
 *   meshcore-cli status                 # one-shot
 *   meshcore-cli set frequency 434.0
 *   meshcore-cli blacklist add ON0XYZ
 *   meshcore-cli                        # interactive (reads lines from stdin)
 *   meshcore-cli -p 4403 status         # override port (or MESHCORE_PORT env)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int send_command(int port, const char *cmd)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "meshcore-cli: cannot connect to 127.0.0.1:%d "
                        "(is the repeater running with control_port set?)\n", port);
        close(fd);
        return 1;
    }

    char out[600];
    int len = snprintf(out, sizeof(out), "%s\n", cmd);
    if (write(fd, out, (size_t)len) < 0) { perror("write"); close(fd); return 1; }
    shutdown(fd, SHUT_WR);

    char buf[1024];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)r, stdout);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    int port = 4403;
    const char *env = getenv("MESHCORE_PORT");
    if (env && *env)
        port = atoi(env);

    int i = 1;
    if (i < argc && !strcmp(argv[i], "-p") && i + 1 < argc) {
        port = atoi(argv[i + 1]);
        i += 2;
    }

    if (i < argc) {                          /* one-shot: join remaining args */
        char cmd[512];
        size_t off = 0;
        for (; i < argc && off < sizeof(cmd) - 1; i++)
            off += (size_t)snprintf(cmd + off, sizeof(cmd) - off, "%s%s",
                                    argv[i], (i + 1 < argc) ? " " : "");
        return send_command(port, cmd);
    }

    /* interactive: one line -> one command */
    char line[512];
    fprintf(stderr, "meshcore-cli -> 127.0.0.1:%d  (commands go to the repeater; "
                    "'exit' quits this client)\n", port);
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;
        if (!strcmp(line, "exit"))
            break;
        send_command(port, line);
    }
    return 0;
}
