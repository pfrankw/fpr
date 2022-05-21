if (CRYPTO)
	add_executable(test_aes test_aes.c)
	target_link_libraries(test_aes fpr mbedcrypto)

	add_executable(test_base64 test_base64.c)
	target_link_libraries(test_base64 fpr mbedcrypto)


	add_executable(test_ecc test_ecc.c)
	target_link_libraries(test_ecc fpr mbedcrypto)

	add_executable(test_rsa test_rsa.c)
	target_link_libraries(test_rsa fpr mbedcrypto)

	add_executable(test_ssl test_ssl.c)
	target_link_libraries(test_ssl fpr mbedtls mbedcrypto mbedx509)
endif()

add_executable(test_http test_http.c)
target_link_libraries(test_http fpr)

add_executable(test_fsm test_fsm.c)
target_link_libraries(test_fsm fpr)

add_executable(test_loop test_loop.c)
target_link_libraries(test_loop fpr)

add_executable(test_stream test_stream.c)
target_link_libraries(test_stream fpr)

add_executable(test_buffer test_buffer.c)
target_link_libraries(test_buffer fpr)

add_executable(massconnect massconnect.c)
target_link_libraries(massconnect fpr)
