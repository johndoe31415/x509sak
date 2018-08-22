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

import hashlib
import collections
import time
from x509sak.BaseAction import BaseAction
from x509sak.Exceptions import InvalidInputException

class ActionHashPart(BaseAction):
	_SupportedHashFunction = collections.namedtuple("SupportedHashFunction", [ "name", "variable_output_length" ])

	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		if len(args.hash_alg) == 0:
			hash_fncs = self.get_default_hash_fncs()
		elif ("all" in args.hash_alg):
			hash_fncs = self.get_supported_hash_fncs()
		else:
			hash_fncs = set(args.hash_alg)

		with open(args.filename, "rb") as f:
			f.seek(args.seek_offset)
			self._data = f.read(args.analysis_length)

		if len(self._args.variable_hash_length) == 0:
			hash_lengths = self.get_default_variable_hash_lengths_bits()
		else:
			hash_lengths = self._args.variable_hash_length
		if any((value % 8) != 0 for value in hash_lengths):
			raise InvalidInputException("Not all hash lengths are evenly divisible by 8: %s" % (", ".join("%d" % (value) for value in hash_lengths)))
		if any((value < 8) for value in hash_lengths):
			raise InvalidInputException("Hash length must be at least 8 bit, not all are: %s" % (", ".join("%d" % (value) for value in hash_lengths)))

		valid_search_chars = set("abcdefABCDEF0123456789")
		if (self._args.search is not None) and (len(set(self._args.search) - valid_search_chars) > 0):
			raise InvalidInputException("Search pattern may only contain hexadecimal characters, but '%s' was given." % (self._args.search))

		self._search = (self._args.search or "").lower()

		t0 = time.time()
		hash_fncs_by_name = { hashfnc.name: hashfnc for hashfnc in self.get_all_supported_hash_fncs() }
		for hash_fnc_name in sorted(hash_fncs):
			hash_fnc = hash_fncs_by_name[hash_fnc_name]
			if not hash_fnc.variable_output_length:
				self._run_hash_function(hash_fnc_name)
			else:
				for hash_len_bits in hash_lengths:
					self._run_hash_function(hash_fnc_name, output_length_bits = hash_len_bits)

		t1 = time.time()
		self._log.debug("Hash search took %.1f secs.", t1 - t0)

	def _run_hash_function(self, hash_fnc_name, output_length_bits = None):
		if output_length_bits is not None:
			output_length_bytes = output_length_bits // 8

		def perform_hashing(hash_data):
			hashfnc = hashlib.new(hash_fnc_name)
			hashfnc.update(hash_data)
			if output_length_bits is None:
				digest = hashfnc.hexdigest()
			else:
				digest = hashfnc.hexdigest(length = output_length_bytes)
			return digest

		if output_length_bits is None:
			full_hash_fnc_name = hash_fnc_name
		else:
			full_hash_fnc_name = "%s-%d" % (hash_fnc_name, output_length_bits)

		for offset in range(len(self._data)):
			for length in range(1, len(self._data) - offset + 1):
				self._run_hash_iteration(full_hash_fnc_name, perform_hashing, offset, length)

	def _run_hash_iteration(self, hash_fnc_name, hash_function, offset, length):
		hash_data = self._data[offset : offset + length]
		hexdigest = hash_function(hash_data)
		if self._search in hexdigest:
			print("%s 0x%x 0x%x 0x%x %s" % (hash_fnc_name, offset, offset + length, length, hexdigest))

	@classmethod
	def get_default_hash_fncs(cls):
		return [ "md5", "sha1", "sha256", "sha384", "sha512" ]

	@classmethod
	def get_default_variable_hash_lengths_bits(cls):
		return [ 128, 256, 384 ]

	@classmethod
	def get_all_supported_hash_fncs(cls):
		def score(text):
			unwanted_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ-")
			score = 0
			for char in text:
				if char in unwanted_chars:
					score += 2

			# Prefer short over long
			score += len(text)
			return score

		constant_len_hashfnc_names = collections.defaultdict(list)
		variable_len_hashfnc_names = collections.defaultdict(list)
		for hashfnc_name in hashlib.algorithms_available:
			try:
				empty_hash = hashlib.new(hashfnc_name).digest()
				constant_len_hashfnc_names[empty_hash].append(hashfnc_name)
			except TypeError:
				empty_hash = hashlib.new(hashfnc_name).digest(length = 16)
				variable_len_hashfnc_names[empty_hash].append(hashfnc_name)


		result = [ ]
		for (hashfnc_name_groups, variable_output_length) in [ (constant_len_hashfnc_names.values(), False), (variable_len_hashfnc_names.values(), True) ]:
			for hashfnc_names in hashfnc_name_groups:
				scored_names = sorted([ (score(name), name) for name in hashfnc_names ])
				chosen_name = scored_names[0][1]
				hash_fnc = cls._SupportedHashFunction(name = chosen_name, variable_output_length = variable_output_length)
				result.append(hash_fnc)
		return result

	@classmethod
	def get_supported_hash_fncs(cls):
		return sorted([ fnc.name for fnc in cls.get_all_supported_hash_fncs() ])
