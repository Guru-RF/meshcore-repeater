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

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>

/* Tab-completion tables (kept in sync with the repeater's CLI by hand). */
static const char *COMMANDS[] = {
    "help", "status", "stats", "neighbors", "channels", "blacklist", "monitor",
    "freq", "set", "get", "advert", "save", "reload", "quit", "exit", NULL
};
static const char *BL_SUB[] = { "add", "remove", "list", NULL };
static const char *CFG_KEYS[] = {
    "frequency", "bandwidth", "spreading_factor", "coding_rate", "tx_power",
    "preamble", "sync_word", "crc", "iq_inverted", "use_cad", "tcxo_voltage",
    "ocp", "name", "advert_interval", "forward", "ping_pong", "control_port",
    "location", "latitude", "longitude", "public_channel", "blacklist", NULL
};

static const char **g_list;   /* which table the active generator walks */

static char *list_generator(const char *text, int state)
{
    static int idx, len;
    if (!state) { idx = 0; len = (int)strlen(text); }
    const char *s;
    while ((s = g_list[idx])) {
        idx++;
        if (strncmp(s, text, (size_t)len) == 0)
            return strdup(s);
    }
    return NULL;
}

/* number of whitespace-separated words fully before position `upto` */
static int words_before(const char *s, int upto)
{
    int w = 0, in = 0;
    for (int i = 0; i < upto; i++) {
        if (s[i] == ' ' || s[i] == '\t') in = 0;
        else if (!in) { in = 1; w++; }
    }
    return w;
}

static char **mc_completer(const char *text, int start, int end)
{
    (void)end;
    rl_attempted_completion_over = 1;         /* never fall back to filenames */
    int w = words_before(rl_line_buffer, start);
    if (w == 0) {                             /* the command itself */
        g_list = COMMANDS;
        return rl_completion_matches(text, list_generator);
    }
    if (w == 1) {                             /* first argument */
        char first[32] = {0};
        sscanf(rl_line_buffer, "%31s", first);
        if (!strcasecmp(first, "blacklist")) { g_list = BL_SUB;   return rl_completion_matches(text, list_generator); }
        if (!strcasecmp(first, "set") ||
            !strcasecmp(first, "get"))        { g_list = CFG_KEYS; return rl_completion_matches(text, list_generator); }
    }
    return NULL;
}
#endif /* HAVE_READLINE */

/* A streaming command (monitor) keeps the connection open and pushes events; the
 * client must NOT half-close its write side, so the daemon detects the client
 * leaving via EOF on read rather than mistaking the half-close for a departure. */
static int is_stream_cmd(const char *s)
{
    return strncmp(s, "monitor", 7) == 0 && (s[7] == '\0' || s[7] == ' ' || s[7] == '\t');
}

static int send_command(int port, const char *cmd)
{
    int stream = is_stream_cmd(cmd);
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
    if (!stream)
        shutdown(fd, SHUT_WR);   /* one-shot: signal done. monitor: keep write open. */

    char buf[1024];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, (size_t)r, stdout);
        fflush(stdout);       /* stream live (monitor) even when piped; a no-op-ish
                                 extra flush for one-shot replies */
    }
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
    fprintf(stderr, "meshcore-cli -> 127.0.0.1:%d  (commands go to the repeater; "
                    "'exit' quits this client)\n", port);
#ifdef HAVE_READLINE
    rl_attempted_completion_function = mc_completer;
    char *l;
    while ((l = readline("meshcore> ")) != NULL) {
        if (*l) {
            add_history(l);
            if (!strcmp(l, "exit")) { free(l); break; }
            send_command(port, l);
        }
        free(l);
    }
#else
    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;
        if (!strcmp(line, "exit"))
            break;
        send_command(port, line);
    }
#endif
    return 0;
}
