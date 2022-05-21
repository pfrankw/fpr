#include <time.h>

#include "fpr/clock.h"


uint64_t fpr_clock()
{
	struct timespec tp;
	uint64_t ret;

	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
		return 0;

	ret = tp.tv_sec * 1000;
	ret += tp.tv_nsec / 1000000;

	return ret;
}
