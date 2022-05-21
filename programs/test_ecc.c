#include <stdio.h>
#include <fpr/pk.h>

#define INPUT_TEXT "I topi non avevano nipoti"
#define INPUT_TEXT_LEN 26

int main()
{
	int r = -1, i;
	struct fpr_pk ecc = { { 0 } };
	uint8_t key[33], sig[200];
	char key_priv[100], key_pub[100];
	size_t sig_len;

	if (fpr_pk_ecc_init_gen(&ecc, MBEDTLS_ECP_DP_SECP256K1) != 0)
		goto exit;

	if (fpr_pk_ecc_to_binary(&ecc, key, sizeof(key), 1) != 0)
		goto exit;

	for (i = 0; i < 33; i++)
		printf("%02x", key[i]);
	printf("\n");

	if (fpr_pk_ecc_to_binary(&ecc, key, sizeof(key), 0) != 0)
		goto exit;

	for (i = 0; i < 32; i++)
		printf("%02x", key[i]);
	printf("\n");

	if (fpr_pk_ecc_to_base64(&ecc, key_pub, sizeof(key_pub), 1) != 0)
		goto exit;

	printf("Public key: %s\n", key_pub);
	if (fpr_pk_ecc_to_base64(&ecc, key_priv, sizeof(key_priv), 0) != 0)
		goto exit;

	printf("Private key: %s\n", key_priv);

	if (fpr_pk_sign_data(&ecc, (uint8_t *)INPUT_TEXT, INPUT_TEXT_LEN, sig, &sig_len) != 0)
		goto exit;

	printf("Signed len = %lu\n", sig_len);

	if (fpr_pk_verify_data(&ecc, (uint8_t *)INPUT_TEXT, INPUT_TEXT_LEN, sig, sig_len) != 0)
		goto exit;

	printf("Verified\n");

	fpr_pk_deinit(&ecc);

	if (fpr_pk_ecc_init_base64(&ecc, MBEDTLS_ECP_DP_SECP256K1, key_pub, 1) != 0)
		goto exit;


	r = 0;
exit:
	printf("R=%d\n", r);
	fpr_pk_deinit(&ecc);
	return r;
}
