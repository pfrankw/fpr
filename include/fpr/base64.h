#ifndef FPR_BASE64_H
#define FPR_BASE64_H


#include <stdint.h>
#include <string.h>


int   fpr_base64_encode(char *base64, size_t base64_len, void *in_data, size_t in_data_len);
int   fpr_base64_decode(const char *base64, void *out_data, size_t *out_data_len);


#endif
