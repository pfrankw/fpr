#include <string.h>

#include "fpr/buffer.h"

#define MIN(a, b) (a<b?a:b)

void fpr_ringbuf_clear(struct fpr_rbuf *rb)
{
	if (!rb)
		return;

	free(rb->buffer);
	memset(rb, 0, sizeof(struct fpr_rbuf));
}

void fpr_ringbuf_init(struct fpr_rbuf *rb, size_t len)
{
	memset(rb, 0, sizeof(struct fpr_rbuf));
	rb->buffer = malloc(len+1);
	rb->len = len+1;
}

static size_t free_len(struct fpr_rbuf *rb)
{
	/* If the head is behind the tail */
	/* =======H============T========= */
	/* else if the head is == with the tail */
	/* ==============TH============== */
	/* else the head is ahead (LOL) of the tail */
	/* ==============T==========H==== */

	if (rb->h < rb->t) {
		return (rb->t - rb->h) - 1;
	} else if (rb->h == rb->t) {
		return rb->len - 1;
	} else {
		return (rb->len-1) - (rb->h-rb->t);
	}
}

static size_t used_len(struct fpr_rbuf *rb)
{
	return (rb->len-1) - free_len(rb);
}

int fpr_ringbuf_write(struct fpr_rbuf *rb, unsigned char *buf, size_t len)
{
	size_t i;

	if (!len)
		return -1;

	if (free_len(rb) < len)
		return -1;

	for (i=0; i<len; i++, rb->h++) {

		if (rb->h == rb->len)
			rb->h = 0;

		rb->buffer[rb->h] = buf[i];
	}

	return 0;
}

int fpr_ringbuf_read(struct fpr_rbuf *rb, unsigned char *buf, size_t len)
{
	size_t i;
	size_t ulen;

	if (!len)
		return -1;

	ulen = used_len(rb);

	for (i=0; i<MIN(len, ulen); i++, rb->t++) {

		if (rb->t == rb->len)
			rb->t = 0;

		buf[i] = rb->buffer[rb->t];
	}

	return (int)i;
}
