#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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

import collections

class FlagChecker():
	_CheckResult = collections.namedtuple("CheckResult", [ "check_type", "reference", "reference_count", "flags" ])

	def __init__(self):
		self._complex_checks = [ ]
		self._may_not_have = set()
		self._must_have = set()
		self._may_have = set()

	def complex_check(self, flags, min_count = None, max_count = None):
		assert((min_count is not None) or (max_count is not None))
		assert((min_count is None) or (min_count >= 0))
		assert((max_count is None) or (max_count <= len(flags)))
		self._complex_checks.append((set(flags), min_count, max_count))
		return self

	def may_have(self, *flags):
		self._may_have |= set(flags)
		return self

	def may_not_have(self, *flags):
		self._may_not_have |= set(flags)
		return self

	def must_have(self, *flags):
		self._must_have |= set(flags)
		return self

	def check(self, flags):
		flag_set = set(flags)
		missing_flags = self._must_have - flag_set
		if len(missing_flags) > 0:
			yield self._CheckResult(check_type = "missing", reference = self._must_have, reference_count = None, flags = missing_flags)

		excess_flags = self._may_not_have & flag_set
		if len(excess_flags) > 0:
			yield self._CheckResult(check_type = "excess", reference = self._may_not_have, reference_count = None, flags = excess_flags)

		unusual_flags = flag_set - self._must_have - self._may_have - self._may_not_have
		for (reference, min_count, max_count) in self._complex_checks:
			unusual_flags = unusual_flags - reference
		if len(unusual_flags) > 0:
			yield self._CheckResult(check_type = "unusual", reference = None, reference_count = None, flags = unusual_flags)

		for (reference, min_count, max_count) in self._complex_checks:
			intersection = reference & flag_set
			count = len(intersection)
			if (min_count is not None) and (count < min_count):
				yield self._CheckResult(check_type = "complex_too_few", reference = reference, reference_count = min_count, flags = intersection)
			if (max_count is not None) and (count > min_count):
				yield self._CheckResult(check_type = "complex_too_many", reference = reference, reference_count = max_count, flags = intersection)
