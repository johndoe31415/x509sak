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

import collections

class BijectiveDict():
	def __init__(self, values):
		self._dict = dict(values)
		self._revdict = { value: key for (key, value) in self._dict.items() }
		if len(self._dict) != len(self._revdict):
			ctr = collections.Counter(self._dict.values())
			dupes = [ element for (element, count) in ctr.items() if count > 1 ]
			raise Exception("Dictionary not bijective: Duplicate values are %s." % (", ".join(dupes)))

	def inverse(self, key):
		return self._revdict[key]

	def get(self, key, surrogate = None):
		return self._dict.get(key, surrogate)

	def __getitem__(self, key):
		return self._dict[key]

	def __len__(self):
		return len(self._dict)

	def __iter__(self):
		return iter(self._dict)
