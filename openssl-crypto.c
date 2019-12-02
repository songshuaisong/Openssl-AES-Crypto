#include <dirent.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUF_SZ 1024

static unsigned char default_ase_key[17] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

void usage()
{
	fprintf(stdout, "Usage: encrpt_isp [-e] | [-d] -i inputfile -o outputfile\n");
	fprintf(stdout, "   -e  encrypt isp file\n");
	fprintf(stdout, "   -d 	decrypt isp file\n");
	fprintf(stdout, "   -i  input isp file\n");
	fprintf(stdout, "   -o 	output isp file\n");

	_exit(0);
}

// input length only support 1024
int encrypt(unsigned char *key, unsigned char *input, int in_length, unsigned char *output)
{
	int result = 0;
	unsigned char iv[16] = {0};
	AES_KEY ass_key;

	memset(&ass_key, 0x00, sizeof(AES_KEY));
	result = AES_set_encrypt_key((const unsigned char *)key, 128, &ass_key);
	if (result < 0)
	{
		printf("encrypt:AES_set_encrypt_key error\r\n");
		return -1;
	}

	AES_cbc_encrypt(input, output, in_length, &ass_key, iv, AES_ENCRYPT);
	return 0;
}

// input length only support 1024
int decrypt(unsigned char *key, unsigned char *input, int in_length, unsigned char *output)
{
	int result = 0;
	unsigned char iv[16] = {0};
	AES_KEY ass_key;

	memset(&ass_key, 0x00, sizeof(AES_KEY));
	result = AES_set_decrypt_key((const unsigned char *)key, 128, &ass_key);
	if (result < 0)
	{
		printf("encrypt:AES_set_encrypt_key error\r\n");
		return -1;
	}

	AES_cbc_encrypt(input, output, in_length, &ass_key, iv, AES_DECRYPT);
	return 0;
}

int get_file_size(char *filename)
{
	int fd;
	struct stat istat;

	fd = open(filename, O_RDONLY, S_IREAD);
	if (fd < 0)
	{
		printf("get_file_size: Unable to open file\n");
		return -1;
	}

	fstat(fd, &istat);
	return istat.st_size;
}

int main(int argc, const char **argv)
{
	int ch;
	int encypt = 0;
	opterr = 0;
	char *infile = NULL, *outfile = NULL;
	unsigned char *tmp = NULL;
	unsigned char inbuf[BUF_SZ + 16] = {0};
	unsigned char outbuf[BUF_SZ + 16] = {0};
	int ifd, ofd, left, file_sz = 0;
	int ret, read_cn, write_cn, i = 0;
	int;

	while ((ch = getopt(argc, (char *const *)argv, "dei:o:")) != -1)
	{
		switch (ch)
		{
		case 'e':
			encypt = 1;
			break;
		case 'd':
			encypt = 0;
			break;
		case 'i':
			infile = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		default:
			usage();
		}
		i++;
	}

	if (optind > argc)
	{
		fprintf(stderr, "%d, Too few arguments to ispen\n", errno);
		usage();
	}

	if (!infile || !outfile)
	{
		fprintf(stderr, "%d, Too few arguments to ispen\n", errno);
		usage();
	}

	ifd = open(infile, O_RDONLY, S_IREAD);
	if (ifd < 0)
	{
		printf("open input file %s error\r\n", infile);
		return -1;
	}

	ofd = creat(outfile, S_IRUSR | S_IWUSR);
	if (ofd < 0)
	{
		printf("Error: Unable to create output file %s\n", outfile);
		close(ifd);
		return 0;
	}

	file_sz = get_file_size(infile);
	if (file_sz < 0)
	{
		printf("get input file size error\r\n");
		goto error;
	}

	while (file_sz > 0)
	{
		memset(inbuf, 0, BUF_SZ);
		memset(outbuf, 0, BUF_SZ);
		file_sz -= BUF_SZ;

		read_cn = read(ifd, (void *)inbuf, BUF_SZ);
		if (read_cn < 0)
		{
			printf("read input file error\r\n");
			goto error;
		}

		if (encypt && (read_cn < BUF_SZ))
		{
			left = read_cn % 16;
			tmp = inbuf + read_cn + left;
			*tmp = left;
			read_cn += left;
			read_cn += 16;
		}

		if (encypt)
			ret = encrypt(default_ase_key, inbuf, read_cn, outbuf);
		else
			ret = decrypt(default_ase_key, inbuf, read_cn, outbuf);

		if (ret < 0)
		{
			printf("encrypt input file error\r\n");
			goto error;
		}

		if (!encypt && (file_sz < 0))
		{
			tmp = outbuf + read_cn - 16;
			read_cn -= 16;
			read_cn -= *tmp;
		}

		write_cn = write(ofd, outbuf, read_cn);
		if (write_cn < 0)
		{
			printf("write output file error\n");
			goto error;
		}
	}

	close(ifd);
	close(ofd);
	return 0;

error:
	close(ifd);
	close(ofd);
	return -1;
}
