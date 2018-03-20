/* This file is AUTO-GENERATED       */
/* Do not edit by hand.              */
/* Your changes will be overwritten. */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "argparse.h"

enum argparse_option_internal_t {
%for opt in [ opt for opt in opts if opt.opt_short is not None ]:
	ARG_${opt.name.upper()}_SHORT = '${opt.opt_short}',
%endfor
%for (oid, opt) in enumerate([ opt for opt in opts if opt.opt_long is not None ], 1000):
	ARG_${opt.name.upper()}_LONG = ${oid},
%endfor
};

bool argparse_parse(int argc, char **argv, argparse_callback_t argument_callback) {
	const char *short_options = "${short_opts_string}";
	struct option long_options[] = {
	%for opt in [ opt for opt in opts if opt.opt_long is not None ]:
		{ ${"%-35s" % ("\"" + opt.opt_long + "\",")} ${"required_argument" if opt.requires_parameter else "no_argument"}, 0, ARG_${opt.name.upper()}_LONG },
	%endfor
		{ 0 }
	};

	while (true) {
		int optval = getopt_long(argc, argv, short_options, long_options, NULL);
		if (optval == -1) {
			break;
		}
		enum argparse_option_internal_t arg = (enum argparse_option_internal_t)optval;
		switch (arg) {
%for opt in opts:
%if opt.opt_short is not None:
			case ARG_${opt.name.upper()}_SHORT:
%endif
%if opt.opt_long is not None:
			case ARG_${opt.name.upper()}_LONG:
%endif
				if (!argument_callback(ARG_${opt.name.upper()}, optarg)) {
					return false;
				}
				break;

%endfor
			default:
				return false;
		}
	}

	/* TODO: Handle positional arguments */

	return true;
}

void argparse_show_syntax(void) {
%for line in help_text:
	fprintf(stderr, "${line.replace('"', '\\"')}\n");
%endfor
}

void argparse_parse_or_die(int argc, char **argv, argparse_callback_t argument_callback) {
	if (!argparse_parse(argc, argv, argument_callback)) {
		argparse_show_syntax();
		exit(EXIT_FAILURE);
	}
}
