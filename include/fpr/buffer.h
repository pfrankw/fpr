#ifndef FPR_BUFFER_H
#define FPR_BUFFER_H

#include <stdint.h>
#include <stdlib.h>

struct fpr_rbuf {
	unsigned char *buffer;
	size_t h, t; /* Head, tail */
	size_t len;
};

void fpr_ringbuf_init(struct fpr_rbuf *rb, size_t len);
void fpr_ringbuf_clear(struct fpr_rbuf *rb);
int fpr_ringbuf_write(struct fpr_rbuf *rb, unsigned char *buf, size_t len);
int fpr_ringbuf_read(struct fpr_rbuf *rb, unsigned char *buf, size_t len);


#endif
