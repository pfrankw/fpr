#ifndef INCLUDE_FPR_UTIL_H_
#define INCLUDE_FPR_UTIL_H_

#include <stdlib.h>

#define AUTO_CALLOC(x) do { (x) = calloc(1, sizeof(*(x))); } while(0);
#define AUTO_MALLOC(x) do { (x) = malloc(sizeof(*(x))); } while(0);


#endif /* INCLUDE_FPR_UTIL_H_ */
