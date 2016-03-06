/*
 * nologin
 *
 * http://www.nologin.org/
 * ----------
 *
 * hashbash is a utility for offline dictionary attacks against message digests.
 * hashbash supports a number of message digest algorithms including sha1 and
 * md5. 
 * 
 * hashbash exhausts all possible upper and lower case letter combinations
 * by calculating and testing all permutations of each word read from the wordlist.
 * To take advantage of this, ensure your wordlist file only contains lower case
 * letters.
 *
 * 12/08/2003
 * Chad Thunberg - chad.thunberg(at)nologin.org
 *
 * compile with gcc -Wall -o hashbash -lm -lcrypto hashbash.c
 */

#include <openssl/evp.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

/* size of the maximum password found in the wordlist */
#define SSIZE 26

/* Prototypes */
void perm(int byte, int count, char *line);
int chk_hash(char *digest, char *hash, char *line);
void usage(void);

int chk_hash(char *digest, char *hash, char *line)
{
	int status = 0;
	int count;
	int byte;
	char hex_output[41] = { 0 };

	EVP_MD_CTX mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;

	count = strlen(line);

	/* Calculate the number of permutations */
	byte = pow(2, strlen(line));
	
	while(byte)
	{
		byte--;

		/* Calculate the permutation */
		perm(byte, count, line);
	
		OpenSSL_add_all_digests();

		/* pass the digest algorithm can be sha1, md5, md4 or md2 */
		md = EVP_get_digestbyname(digest);

		/* This condition should never be reached */
		if(!md)
		{
			printf("Unknown message digest %s\n", digest);
			exit(EXIT_FAILURE);
	    	}

		EVP_DigestInit(&mdctx, md);
		EVP_DigestUpdate(&mdctx, line, strlen(line));
		EVP_DigestFinal(&mdctx, md_value, &md_len);

		for(i = 0; i < md_len; i++)
		{
			sprintf(hex_output + i * 2, "%02x", md_value[i]);
		}

		if (strcmp(hex_output, hash) == 0)
		{
			status = 1;
			break;
		}
	}
	return status;
}

void perm(int byte, int count, char *line)
{
	/* Convert decimal to binary and change the case */
	int length = strlen(line) - 1;
	int mask = (1 << (count-1));

	while(count--)
	{
		if(byte & mask)
		{
			line[length-count] = toupper(line[length-count]);
		} else {
			line[length-count] = tolower(line[length-count]);	
		}
	byte <<= 1;
	}
	return;
}

void usage(void)
{
	fprintf(stderr, "Usage: hashbash [-d <algorithm>] [-h hash] [-w wordlist]\n");
	fprintf(stderr, "algorithms: md2, md4, md5, sha, sha1, dss1, mdc2 or ripemd160\n\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int op;
	char *hash = NULL;
	char *filename = NULL;
	char *digest = NULL;
	char line[SSIZE + 1];
	FILE *fptr;

	/* supress getopt's error messages */
	opterr = 0;

	if(argc == 1)
	{
		usage();
	}

	while ((op = getopt(argc, argv, "d:h:w:")) != -1)
	{
		switch(op)
		{
			case 'd':
				digest = optarg;
				break;
			case 'h':
				hash = optarg;
				break;
			case 'w':
				filename = optarg;
				break;
			case '?':
				usage();
			default:
				usage();
		}
	}

	if(strcmp(digest, "md5") && strcmp(digest, "md4") && strcmp(digest, "md2") \
	&& strcmp(digest, "sha") && strcmp(digest, "sha1") && strcmp(digest, "dss1") && \
	strcmp(digest, "mdc2") && strcmp(digest, "ripemd160") != 0)
	{
		usage();
	}


	if(filename == NULL)
	{
		usage();
	}

	if ((fptr = fopen(filename, "r")) == NULL)
	{
		fprintf(stderr, "Opening file, '%s', failed\n", filename);
		exit(EXIT_FAILURE);
	}

	while (fgets(line, SSIZE, fptr) != NULL)
	{
		/* Get rid of the '\n' we just copied from the dictionary file */
		line[strlen(line)-1] = '\0';

		/* If status returns 1, then we have a match */
		if((chk_hash(digest, hash, line)) == 1)	
		{
			fprintf(stdout, "The hash, '%s', matches the string '%s'\n", hash, line);
			fclose(fptr);
			exit(EXIT_SUCCESS);
		}
	}
	printf("The hash '%s' matched no results\n", hash);
	fclose(fptr);
	return 1;
}
