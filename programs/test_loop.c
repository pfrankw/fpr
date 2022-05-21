#include <stdio.h>
#include <signal.h>

#include <fpr/loop.h>


static int g_run = 1;

static void cb(void *arg)
{
	printf("TEST\n");
}

static void sig_handler(int sig)
{
	printf("SIGNAL\n");
	if (sig == SIGINT)
		g_run = 0;
}

int main()
{
	fpr_loop *loop = NULL;

	signal(SIGINT, sig_handler);

	loop = fpr_loop_new();

	fpr_loop_add_timer(loop, 1000, 0, cb, NULL);

	while (g_run)
		fpr_loop_run(loop);


	fpr_loop_free(loop);
}
