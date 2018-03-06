#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <gmp.h>

#include "primegen.h"
#include "pgmopts.h"

static void *find_prime_thread(void *vthread_data) {
	mpz_t number;
	mpz_init2(number, 1024);


	for (int i = 0; i < 1000; i++) {

		if (mpz_probab_prime_p(number, 10)) {
			gmp_printf("value = %Zd\n", number);
		}
	}

	mpz_clear(number);

	return NULL;
}

int main(int argc, char **argv) {
	if (!parse_opts(argc, argv)) {
		exit(EXIT_FAILURE);
	}

	find_prime_thread(NULL);

	return 0;
}
