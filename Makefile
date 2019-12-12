build:
	gcc openssl-crypto.c -Werror -Wall -o openssl-crypto -lcrypto
test:
	@echo success!
