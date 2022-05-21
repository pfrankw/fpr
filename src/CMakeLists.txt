if (CRYPTO)
	message("CRYPTO ENABLED")
	SET(CRYPTO_SRC 
		base64.c
		crypto/aes.c
		crypto/pk.c
		crypto/pk_ecc.c
		crypto/random.c
		crypto/sha1.c
		crypto/sha256.c
		crypto/sha512.c
		crypto/ssl.c
		crypto/x509.c
	)
endif()

add_library(fpr
	buffer.c clock.c fsm.c
	http.c loop.c
	stream.c

	${CRYPTO_SRC}
)
