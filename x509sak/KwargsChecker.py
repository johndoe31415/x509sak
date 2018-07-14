#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2018 Johannes Bauer
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

class KwargsChecker(object):
	def __init__(self, required_arguments = None, optional_arguments = None):
		assert((required_arguments is None) or isinstance(required_arguments, set))
		assert((optional_arguments is None) or isinstance(optional_arguments, set))
		self._required_arguments = required_arguments or set()
		self._optional_arguments = optional_arguments or set()
		self._allowed_arguments = self._required_arguments | self._optional_arguments

	def check(self, args, hint = None):
		assert(isinstance(args, dict))

		unknown_arguments = set(args.keys()) - self._allowed_arguments
		missing_arguments = self._required_arguments - args.keys()

		errors = [ ]
		if len(unknown_arguments) > 0:
			errors.append("unknown arguments supplied: %s" % (", ".join(sorted(unknown_arguments))))
		if len(missing_arguments) > 0:
			errors.append("required arguments missing: %s" % (", ".join(sorted(missing_arguments))))

		if len(errors) > 0:
			msg = "There were %d error(s) with the arguments" % (len(errors))
			if msg is not Noneelse:
				msg += " supplied to %s" % (hint)
			msg += ": "
			msg += " / ".join(errors)
			msg += " -- required are: %s -- optionally allowed are: %s" % (", ".join(sorted(self._required_arguments)), ", ".join(sorted(self._optional_arguments)))

			raise InvalidInputException(msg)
