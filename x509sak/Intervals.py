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

import enum
import bisect

class IntervalConstraintException(Exception): pass
class IntervalIdenticalException(IntervalConstraintException): pass
class IntervalOverlapsException(IntervalConstraintException): pass

class IntervalRelation(enum.IntEnum):
	Disjunct = 0
	Identical = 1
	Overlapping = 2
	Contained = 3
	Container = 4

class Interval(object):
	def __init__(self, begin, end, data = None):
		"""'begin' is inclusive, 'end' is exclusive."""
		assert(isinstance(begin, int))
		assert(isinstance(end, int))
		assert(end > begin)
		self._begin = begin
		self._end = end
		self._data = data

	@classmethod
	def begin_length(cls, begin, length, data = None):
		return cls(begin = begin, end = begin + length, data = data)

	@property
	def begin(self):
		return self._begin

	@property
	def end(self):
		return self._end

	@property
	def data(self):
		return self._data

	@property
	def cmpkey(self):
		return (self.begin, self.end)

	@property
	def length(self):
		return self.end - self.begin

	def enumerate_members(self):
		return range(self.begin, self.end)

	def relation_to(self, other):
		if (self.begin, self.end) == (other.begin, other.end):
			return IntervalRelation.Identical
		elif (other.begin >= self.end) or (other.end <= self.begin):
			return IntervalRelation.Disjunct
		elif (self.begin <= other.begin < self.end) and (self.begin <= other.end <= self.end):
			# self contains other
			return IntervalRelation.Container
		elif (other.begin <= self.begin < other.end) and (other.begin <= self.end <= other.end):
			# self contained in other
			return IntervalRelation.Contained
		else:
			return IntervalRelation.Overlapping

	def __eq__(self, other):
		return self.cmpkey == other.cmpkey

	def __neq__(self, other):
		return not (self == other)

	def __lt__(self, other):
		return self.cmpkey < other.cmpkey

	def __hash__(self):
		return hash(self.cmpkey)

	def __repr__(self):
		return "Interval(%d, %d)" % (self.begin, self.end)

class Intervals(object):
	def __init__(self, allow_overlapping = True, allow_identical = True):
		self._allow_overlapping = allow_overlapping
		self._allow_identical = allow_identical
		self._intervals = [ ]

	@property
	def allow_overlapping(self):
		return self._allow_overlapping

	@property
	def allow_identical(self):
		return self._allow_identical

	def enumerate_members(self):
		for interval in self._intervals:
			yield from interval.enumerate_members()

	def add(self, interval):
		assert(isinstance(interval, Interval))
		if (not self.allow_identical) and self.relation_to_any_subinterval(interval, (IntervalRelation.Identical, )):
			raise IntervalIdenticalException("Cannot add interval %s, identical interval already present." % (interval))
		if (not self.allow_overlapping) and self.relation_to_any_subinterval(interval, (IntervalRelation.Identical, IntervalRelation.Overlapping, IntervalRelation.Container, IntervalRelation.Contained)):
			raise IntervalIdenticalException("Cannot add interval %s, some form of overlapping with present intervals." % (interval))
		bisect.insort(self._intervals, interval)

	def find_interacting(self, interval):
		assert(isinstance(interval, Interval))
		index = max(bisect.bisect(self._intervals, Interval(interval.begin, interval.begin + 1)) - 1, 0)
		while index < len(self._intervals):
			candidate = self[index]
			if (candidate.begin < interval.end) and (candidate.end > interval.begin):
				yield candidate
			elif candidate.begin >= interval.end:
				# No more matches possible
				break
			index += 1

	def relation_to_any_subinterval(self, interval, expected_relations):
		for interacting in self.find_interacting(interval):
			relation = interacting.relation_to(interval)
			if relation in expected_relations:
				return True
		return False

	def fully_contained_in_subinterval(self, interval):
		return self.relation_to_any_subinterval(interval, (IntervalRelation.Container, IntervalRelation.Identical))

	def __getitem__(self, index):
		return self._intervals[index]

	def dump(self):
		print("%d intervals total:" % (len(self._intervals)))
		for (index, interval) in enumerate(self._intervals):
			print("   %2d: %s" % (index, interval))
