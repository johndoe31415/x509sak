#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2020 Johannes Bauer
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

from x509sak.Exceptions import InvalidInternalDataException

class BijectiveDictException(InvalidInternalDataException): pass

class BijectiveDict():
	def __init__(self, values, key_predicate = None, value_predicate = None):
		self._key_predicate = key_predicate if (key_predicate is not None) else lambda key: key
		self._value_predicate = value_predicate if (value_predicate is not None) else lambda value: value
		self._lookup_dict = { self._key_predicate(key): value for (key, value) in values.items() }
		self._lookup_revdict = { self._value_predicate(value): key for (key, value) in values.items() }
		if len(values) != len(self._lookup_dict):
			raise BijectiveDictException("Dictionary has duplicate keys after application of key predicate.")

		if len(values) != len(self._lookup_revdict):
			raise BijectiveDictException("Dictionary not bijective.")

	def keys(self):
		return self._lookup_dict.keys()

	def inverse(self, value):
		value = self._value_predicate(value)
		return self._lookup_revdict[value]

	def get(self, key, surrogate = None):
		key = self._key_predicate(key)
		return self._lookup_dict.get(key, surrogate)

	def __getitem__(self, key):
		key = self._key_predicate(key)
		return self._lookup_dict[key]

	def __len__(self):
		return len(self._lookup_dict)

	def __iter__(self):
		return iter(self._lookup_dict)
