#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "pgmopts.h"
#include "argparse.h"

static struct pgmopts_t pgmopts_rw = {
	.genmode = MODE_RANDOM,
	.threads = 8,
	.prime_bits = 2048,
	.prime_type = PRIMETYPE_2_MSB,
	.prime_count = 10,
};
const struct pgmopts_t *pgmopts = &pgmopts_rw;

static bool parse_callback(enum argparse_option_t option, const char *value) {
	switch (option) {
		case ARG_MODE:
			if (!strcmp(value, "random")) {
				pgmopts_rw.genmode = MODE_RANDOM;
			} else if (!strcmp(value, "crt")) {
				pgmopts_rw.genmode = MODE_CRT;
			} else {
				return false;
			}
			break;

		case ARG_PRIME_TYPE:
			if (!strcmp(value, "2msb")) {
				pgmopts_rw.prime_type = PRIMETYPE_2_MSB;
			} else if (!strcmp(value, "3msb")) {
				pgmopts_rw.prime_type = PRIMETYPE_3_MSB;
			} else {
				return false;
			}
			break;

		case ARG_THREAD_CNT:
			pgmopts_rw.threads = atoi(value);
			if ((pgmopts_rw.threads < 1) || (pgmopts_rw.threads > 1024)) {
				fprintf(stderr, "Thread count must be in between 1 and 1024.\n");
				return false;
			}
			break;

		case ARG_BIT_LENGTH:
			pgmopts_rw.prime_bits = atoi(value);
			if (pgmopts_rw.prime_bits < 8) {
				fprintf(stderr, "Primes must be at least 8 bit.\n");
				return false;
			}
			break;

		case ARG_NUM_PRIMES:
			pgmopts_rw.prime_count = atoi(value);
			break;
	}
	return true;
}

void parse_opts(int argc, char **argv) {
	argparse_parse_or_die(argc, argv, parse_callback);
}
