#!/usr/bin/python3
import sys
import os
import textwrap
import collections
import importlib.util
import mako.lookup
from FriendlyArgumentParser import FriendlyArgumentParser

class CodeGenerator(object):
	_Option = collections.namedtuple("Option", [ "name", "requires_parameter", "opt_short", "opt_long" ])

	def __init__(self, args):
		self._args = args
		self._parser = self._load_submodule()
		self._options = self._parse_parser()

	def _parse_parser(self):
		options = [ ]
		for action in self._parser._actions:
			opt_short = None
			opt_long = None
			for option in action.option_strings:
				if option.startswith("--"):
					# Long options
					opt_long = option[2:]
				elif (len(option) == 2) and (option[0] == "-"):
					# Short option
					opt_short = option[1]
				else:
					raise Exception("Unknown option: '%s'." % (option))

			option = self._Option(name = action.dest, requires_parameter = (action.nargs != 0), opt_short = opt_short, opt_long = opt_long)
			options.append(option)
		return options

	def _load_submodule(self):
		spec = importlib.util.spec_from_file_location("parsermodule", self._args.parser)
		parsermodule = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(parsermodule)
		return parsermodule.parser

	@property
	def short_opts_string(self):
		string = ""
		for opt in self._options:
			if opt.opt_short is not None:
				string += opt.opt_short
				if opt.requires_parameter:
					string += ":"
		return string

	def run(self):
		lookup = mako.lookup.TemplateLookup([ "." ], strict_undefined = True)
		args = {
			"opts":					self._options,
			"short_opts_string":	self.short_opts_string,
			"help_text":			self._parser.format_help().rstrip("\r\n").split("\n"),
		}

		for suffix in [ ".c", ".h" ]:
			template = lookup.get_template("argparse_template" + suffix)
			result = template.render(**args)
			with open("argparse" + suffix, "w") as f:
				f.write(result)


parser = FriendlyArgumentParser(prog = "getoptgen", description = "getoptgen - Generate getopt-style C code from Python argparse", add_help = False)
parser.add_argument("parser", type = str, help = "Python code which contains the parser definition.")
args = parser.parse_args(sys.argv[1:])
CodeGenerator(args).run()

