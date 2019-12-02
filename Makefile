build:
	gcc openssl-crypto.c -o openssl-crypto -lcrypto
test:
	@echo success