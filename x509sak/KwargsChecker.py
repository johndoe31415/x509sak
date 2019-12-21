#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
#
#	This file is part of x509sak.
#
#	x509sak is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	x509sak is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with x509sak; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

from x509sak.Exceptions import InvalidInputException

class KwargsChecker():
	def __init__(self, required_arguments = None, optional_arguments = None):
		assert((required_arguments is None) or isinstance(required_arguments, set))
		assert((optional_arguments is None) or isinstance(optional_arguments, set))
		self._required_arguments = required_arguments or set()
		self._optional_arguments = optional_arguments or set()
		self._allowed_arguments = self._required_arguments | self._optional_arguments

	def check_single(self, arg, hint = None):
		if arg not in self._allowed_arguments:
			if hint is None:
				raise InvalidInputException("%s is not a valid argument." % (arg))
			else:
				raise InvalidInputException("%s is not a valid argument for %s." % (arg, hint))

	def check(self, args, hint = None):
		args = set(args)
		unknown_arguments = args - self._allowed_arguments
		missing_arguments = self._required_arguments - args

		errors = [ ]
		if len(unknown_arguments) > 0:
			if len(unknown_arguments) == 1:
				errors.append("unknown argument: %s" % (list(unknown_arguments)[0]))
			else:
				errors.append("%d unknown arguments: %s" % (len(unknown_arguments), ", ".join(sorted(unknown_arguments))))
		if len(missing_arguments) > 0:
			errors.append("required argument(s) missing: %s" % (", ".join(sorted(missing_arguments))))

		if len(errors) > 0:
			if len(errors) == 1:
				msg = "There was an error with the arguments"
			else:
				msg = "There were %d error(s) with the arguments" % (len(errors))
			if hint is not None:
				msg += " supplied to %s" % (hint)
			msg += ": "
			msg += " / ".join(errors)
			if len(self._required_arguments) > 0:
				msg += " -- required are: %s" % (", ".join(sorted(self._required_arguments)))
			if len(self._optional_arguments) > 0:
				msg += " -- allowed are: %s" % (", ".join(sorted(self._optional_arguments)))
			raise InvalidInputException(msg)
