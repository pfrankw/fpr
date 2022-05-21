#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <fpr/loop.h>

#include <utlist.h>

struct connctx {
    int fd;
    int state;
    struct fpr_io *io;
    struct fpr_timer *timer;

    char *ip;
    int port;

    char *hello;
    char *bannercheck;

    char buf[128];
    int bufi;

    int found;


    struct connctx *prev, *next;
};

enum {
    STATE_WAIT = 0,
    STATE_READY
};

#define MAXCONNS 500
static struct connctx *connlist = NULL;
static fpr_loop *loop = NULL;
static FILE *fp = NULL;
static FILE *fpout = NULL;
static unsigned int iline = 0;

static void addconn();

static int tcp4_async_connect(char *ip, int port)
{
    int sock, r;
	struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
    if (sock == -1)
        return -1;

    server.sin_addr.s_addr = inet_addr(ip);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

    r = connect(sock, (struct sockaddr*)&server, sizeof(server));

    if (r == 0)
        return sock;

    if (errno == EINPROGRESS)
        return sock;

    close(sock);
    return -1;
}

static void delconn(struct connctx *cc)
{
    DL_DELETE(connlist, cc);
    fpr_loop_del_io(loop, cc->io);
    fpr_loop_del_timer(loop, cc->timer);

    close(cc->fd);
    free(cc->ip);
    free(cc);
}

static void iocb(uint8_t rev, void *arg)
{
    struct connctx *cc = arg;
    char buf[4] = {0};

    switch (cc->state) {

    case STATE_WAIT:

        if (rev & FPR_IO_EVERROR) {
            delconn(cc);
            break;
        }

        if (rev & FPR_IO_EVWRITE) {
            cc->state = STATE_READY;
            write(cc->fd, cc->hello, strlen(cc->hello));
        }

        break;


    case STATE_READY:

        if (rev & FPR_IO_EVREAD) {
            int r;


            r = read(cc->fd, buf, sizeof(buf));
            fprintf(stdout, "%s:%d is readable %d\n", cc->ip, cc->port, r);

            if (r > 0) {

                if (r+cc->bufi < (sizeof(cc->buf)-1)) {
                    memcpy(cc->buf+cc->bufi, buf, r);
                    cc->bufi += r;
                }

                if (strstr(cc->buf, cc->bannercheck)) {
                    cc->found = 1;
                    fprintf(fpout, "%s:%d\n", cc->ip, cc->port);
                    fflush(fpout);
                    delconn(cc);
                }

            } else if (r <= 0) {
                delconn(cc);
            }

        }
    }

    addconn();
}

//open tcp 3128 178.203.115.106 1562854119
static void addconn()
{
    int r;
    int c;
    struct connctx *tmp;
    char line [1024];

    DL_COUNT(connlist, tmp, c);

    if (c >= MAXCONNS)
        return;


    if (fgets(line, sizeof(line), fp) != NULL)
    {
        int port;
        char ip[30];
        int fd;
        struct connctx *cc;

        r = sscanf(line, "%*s %*s %d %s %*s", &port, ip);

        if (r != 2)
            return;


        fd = tcp4_async_connect(ip, port);
        if (fd == -1)
            return;

        fprintf(stdout, "Trying conn at %s:%d\n", ip, port);

        cc = calloc(1, sizeof(*cc));
        cc->fd = fd;
        cc->ip = strdup(ip);
        cc->port = port;
        cc->hello = "CONNECT www.google.com:80 HTTP/1.0\r\n\r\n";
        cc->bannercheck = "200 OK";

        DL_APPEND(connlist, cc);
        cc->io = fpr_loop_add_io(loop, fd, FPR_IO_EVREAD|FPR_IO_EVWRITE, iocb, cc);
        // After 10 seconds of no activity we delete it
        cc->timer = fpr_loop_add_timer(loop, 20000, FPR_TIMER_FLAG_ONCE, (fpr_timer_cb)delconn, cc);

        iline++;
        fprintf(stderr, "\r                                \r%u hosts contacted", iline);
    }

}

// Usage: massconnect scan.txt res.txt
int main(int argc, char **argv)
{
    int i;

    if (argc < 3)
        return -1;

    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stdout, "Cant open file\n");
        return -1;
    }

    fpout = fopen(argv[2], "w");
    if (!fpout)
        return -1;

    loop = fpr_loop_new();

    for (i=0; i<MAXCONNS; i++) {
        addconn();
    }

    while(1)
        fpr_loop_run(loop);

    fclose(fp);
    fclose(fpout);
    fpr_loop_free(loop);
}
