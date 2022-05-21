#include <stdio.h>
#include <string.h>

#include <fpr/buffer.h>

#define BUF_LEN 10
#define FIRST_STR "i topi"
#define SECOND_STR " non ave"
#define THIRD_STR "vano nipo"
#define FOURTH_STR "ti"
#define FIFTH_STR "i topi non"


static int test_write_read_str(struct fpr_rbuf *rb, char *str)
{
	unsigned char buf[strlen(str)*100];

	if (fpr_ringbuf_write(rb, (unsigned char*)str, strlen(str)) != 0)
		return -1;

	if (fpr_ringbuf_read(rb, buf, sizeof(buf)) != strlen(str))
		return -1;

	if (memcmp(buf, str, strlen(str)) != 0)
		return -1;

	return 0;
}

int main(void)
{
	int r = -1;
	struct fpr_rbuf rb;

	fpr_ringbuf_init(&rb, BUF_LEN);

	if (test_write_read_str(&rb, FIRST_STR) != 0)
		goto cleanup;

	if (test_write_read_str(&rb, SECOND_STR) != 0)
		goto cleanup;

	if (test_write_read_str(&rb, THIRD_STR) != 0)
		goto cleanup;

	if (test_write_read_str(&rb, FOURTH_STR) != 0)
		goto cleanup;

	if (test_write_read_str(&rb, FIFTH_STR) != 0)
		goto cleanup;

	r = 0;
cleanup:
	fpr_ringbuf_clear(&rb);
	printf("r=%d\n", r);
	return r;
}
