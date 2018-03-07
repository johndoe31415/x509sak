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

		case ARG_THREAD_CNT:
			pgmopts_rw.threads = atoi(value);
			break;

		case ARG_BIT_LENGTH:
			pgmopts_rw.prime_bits = atoi(value);
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
