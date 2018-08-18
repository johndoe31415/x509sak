#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <gmp.h>

#include "primegen.h"
#include "pgmopts.h"

struct shared_thread_data_t {
	pthread_mutex_t global_lock;
	unsigned int found_primes;
	bool quit;
	double start_time;
};

struct thread_data_t {
	pthread_t thread;
	struct shared_thread_data_t *shared;
	uint64_t candidates;
};

static double now(void) {
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		return 0;
	}
	return tv.tv_sec + (1e-6 * tv.tv_usec);
}

static bool mpz_randomize_prime_candidate(mpz_t number, unsigned int bits, enum primetype_t prime_type) {
	uint8_t random_data[(bits + 7) / 8];
	int fd = open("/dev/urandom", O_RDONLY);
	if (bits < 8) {
		fprintf(stderr, "Bits must be at least 8.\n");
		return false;
	}
	if (fd == -1) {
		perror("/dev/urandom");
		return false;
	}
	if (read(fd, random_data, sizeof(random_data)) != sizeof(random_data)) {
		perror("urandom read");
		return false;
	}
	if ((bits % 8) != 0) {
		uint8_t msb_mask = (1 << (bits % 8)) - 1;
		random_data[0] &= msb_mask;
	}
	mpz_import(number, sizeof(random_data), 1, 1, 0, 0, random_data);

	/* Set LSB always (odd prime) and the top three MSB to either 0b110 or
	 * 0b111 (depending on the type) */
	mpz_setbit(number, 0);
	switch (prime_type) {
		case PRIMETYPE_2_MSB:
			mpz_setbit(number, bits - 1);
			mpz_setbit(number, bits - 2);
			mpz_clrbit(number, bits - 3);
			break;

		case PRIMETYPE_3_MSB:
			mpz_setbit(number, bits - 1);
			mpz_setbit(number, bits - 2);
			mpz_setbit(number, bits - 3);
			break;
	}

	close(fd);
	return true;
}

static void generate_odd_prime_product(mpz_t result, unsigned int bits) {
	mpz_t prime;
	mpz_init_set_ui(prime, 2);
	mpz_set_ui(result, 1);
	while (true) {
		mpz_nextprime(prime, prime);
		mpz_mul(result, result, prime);
		if (mpz_sizeinbase(result, 2) >= bits) {
			/* Stay under that amount of bits */
			mpz_div(result, result, prime);
			break;
		}
	}
	mpz_clear(prime);
}

static bool export_prime(struct thread_data_t *thread_data, mpz_t prime, enum primetype_t prime_type) {
	pthread_mutex_lock(&thread_data->shared->global_lock);
	char filename[128];
	long length_bits = mpz_sizeinbase(prime, 2);
	const char *prime_type_str = "unknown";
	switch (prime_type) {
		case PRIMETYPE_2_MSB:	prime_type_str = "2msb"; break;
		case PRIMETYPE_3_MSB:	prime_type_str = "3msb"; break;
	}
	snprintf(filename, sizeof(filename), "primes_%s_%ld.txt", prime_type_str, length_bits);

	FILE *f = fopen(filename, "a");
	if (!f) {
		perror(filename);
		return false;
	}
	gmp_fprintf(f, "%Zx\n", prime);
	fclose(f);

	thread_data->shared->found_primes++;
	double tdiff = now() - thread_data->shared->start_time;
	fprintf(stderr, "%d of %d (%.0f%%) in %.0f seconds (%.0f seconds/prime); just found %lu bit prime.\n", thread_data->shared->found_primes, pgmopts->prime_count, 100. * thread_data->shared->found_primes / pgmopts->prime_count, tdiff, tdiff / thread_data->shared->found_primes, mpz_sizeinbase(prime, 2));

	pthread_mutex_unlock(&thread_data->shared->global_lock);
	return true;
}

static void *find_primes_random(void *vthread_data) {
	struct thread_data_t *thread_data = (struct thread_data_t*)vthread_data;

	mpz_t candidate, oddprimes, gcd;
	mpz_init(candidate);
	mpz_init(oddprimes);
	mpz_init(gcd);

	//generate_odd_prime_product(oddprimes, pgmopts->prime_bits);
	generate_odd_prime_product(oddprimes, 64);

	mpz_randomize_prime_candidate(candidate, pgmopts->prime_bits, pgmopts->prime_type);
	while ((!thread_data->shared->quit) && (thread_data->shared->found_primes < pgmopts->prime_count)) {
		thread_data->candidates++;
		mpz_gcd(gcd, candidate, oddprimes);
		if (mpz_cmp_ui(gcd, 1) == 0) {
			if (mpz_probab_prime_p(candidate, 10)) {
				export_prime(thread_data, candidate, pgmopts->prime_type);
				mpz_randomize_prime_candidate(candidate, pgmopts->prime_bits, pgmopts->prime_type);
			}
		}
		mpz_add_ui(candidate, candidate, 2);
	}

	mpz_clear(oddprimes);
	mpz_clear(candidate);

	return NULL;
}

static void *find_primes_crt(void *vthread_data) {
	struct thread_data_t *thread_data = (struct thread_data_t*)vthread_data;
	const unsigned int max_prime_cnt = 5000;
	unsigned int prime_cnt = 0;
	unsigned int primes[max_prime_cnt];
	mpz_t prime_product;
	mpz_t next_prime;
	mpz_init_set_ui(prime_product, 1);
	mpz_init_set_ui(next_prime, 2);
	while (prime_cnt < max_prime_cnt) {
		primes[prime_cnt] = mpz_getlimbn(next_prime, 0);
		mpz_mul_ui(prime_product, prime_product, primes[prime_cnt]);
		mpz_nextprime(next_prime, next_prime);
		prime_cnt++;
		if (mpz_sizeinbase(prime_product, 2) >= pgmopts->prime_bits) {
			break;
		}
	}
	mpz_clear(next_prime);

	while ((!thread_data->shared->quit) && (thread_data->shared->found_primes < pgmopts->prime_count)) {
		mpz_t sum;
		mpz_init(sum);
		for (int i = 0; i < prime_cnt - 1; i++) {
			mpz_t ring, inverse;
			mpz_init(ring);
			mpz_init(inverse);

			mpz_div_ui(ring, prime_product, primes[i]);
			mpz_set_ui(inverse, primes[i]);
			mpz_invert(inverse, ring, inverse);
			unsigned int remainder = 1 + (rand() % (primes[i] - 1));

			// sum += ring * inverse * remainder
			mpz_mul(ring, ring, inverse);
			mpz_mul_ui(ring, ring, remainder);
			mpz_add(sum, sum, ring);

			mpz_clear(inverse);
			mpz_clear(ring);
		}

		mpz_t ring, inverse, candidate;
		mpz_init(ring);
		mpz_init(inverse);
		mpz_init(candidate);

		mpz_div_ui(ring, prime_product, primes[prime_cnt - 1]);
		mpz_set_ui(inverse, primes[prime_cnt - 1]);
		mpz_invert(inverse, ring, inverse);
		mpz_mul(ring, ring, inverse);
		mpz_clear(inverse);

		mpz_t last_factor;
		mpz_init(last_factor);

		for (int last_remainder = 1; last_remainder < primes[prime_cnt - 1]; last_remainder++) {
			thread_data->candidates++;
			mpz_mul_ui(last_factor, ring, last_remainder);
			mpz_add(candidate, sum, last_factor);
			if (mpz_probab_prime_p(candidate, 10)) {
				export_prime(thread_data, candidate, pgmopts->prime_type);
			}

			if ((thread_data->shared->quit) || (thread_data->shared->found_primes >= pgmopts->prime_count)) {
				break;
			}
		}

		mpz_clear(last_factor);
		mpz_clear(sum);
	}

	mpz_clear(prime_product);
	return NULL;
}


int main(int argc, char **argv) {
	parse_opts(argc, argv);
	fprintf(stderr, "Generating %d %d-bit primes with %d threads in %s mode.\n", pgmopts->prime_count, pgmopts->prime_bits, pgmopts->threads, pgmopts->genmode == MODE_RANDOM ? "random" : "CRT");

	srand(time(NULL));

	pthread_mutex_t global_lock;
	pthread_mutex_init(&global_lock, NULL);

	struct shared_thread_data_t shared;
	memset(&shared, 0, sizeof(shared));
	shared.start_time = now();

	struct thread_data_t thread_data[pgmopts->threads];
	memset(&thread_data, 0, sizeof(thread_data));
	for (int i = 0; i < pgmopts->threads; i++) {
		thread_data[i].shared = &shared;
		if (pgmopts->genmode == MODE_RANDOM) {
			pthread_create(&thread_data[i].thread, NULL, find_primes_random, thread_data + i);
		} else {
			pthread_create(&thread_data[i].thread, NULL, find_primes_crt, thread_data + i);
		}
	}
	uint32_t seconds = 0;
	while (!shared.quit && (shared.found_primes < pgmopts->prime_count)) {
		seconds++;
		sleep(1);
		if ((seconds % 10) == 0) {
			pthread_mutex_lock(&shared.global_lock);
			double tdiff = now() - thread_data->shared->start_time;
			uint64_t total_candidates = 0;
				for (int i = 0; i < pgmopts->threads; i++) {
				total_candidates += thread_data[i].candidates;
			}
			fprintf(stderr, "%lu candidates in %.0f secs (%.1f candidates/sec)\n", total_candidates, tdiff, total_candidates / tdiff);
			pthread_mutex_unlock(&shared.global_lock);
		}
	}
	double tdiff = now() - thread_data->shared->start_time;
	fprintf(stderr, "Finished after %.0f secs (%.1f seconds/prime)\n", tdiff, tdiff / pgmopts->prime_count);
	for (int i = 0; i < pgmopts->threads; i++) {
		pthread_join(thread_data[i].thread, NULL);
	}
	return 0;
}
