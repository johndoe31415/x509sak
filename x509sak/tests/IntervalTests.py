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

from x509sak.tests import BaseTest
from x509sak.Intervals import IntervalConstraintException, IntervalRelation, Interval, Intervals

class IntervalTests(BaseTest):
	def test_interval_comparison(self):
		self.assertLess(Interval(0, 1), Interval(0, 2))
		self.assertLess(Interval(0, 1), Interval(1, 2))
		self.assertEqual(Interval(0, 10), Interval(0, 10))
		self.assertEqual(Interval(10, 20), Interval(10, 20))
		self.assertNotEqual(Interval(0, 1), Interval(0, 2))

	def assertIntervalRelation(self, intvl1, intvl2, relation):
		self.assertEqual(intvl1.relation_to(intvl2), relation)
		inv_relation = {
			IntervalRelation.Contained:	IntervalRelation.Container,
			IntervalRelation.Container:	IntervalRelation.Contained,
		}.get(relation, relation)
		self.assertEqual(intvl2.relation_to(intvl1), inv_relation)

	def test_interval_relation_disjunct(self):
		self.assertIntervalRelation(Interval(0, 10), Interval(100, 200), IntervalRelation.Disjunct)
		self.assertIntervalRelation(Interval(100, 200), Interval(0, 10), IntervalRelation.Disjunct)
		self.assertIntervalRelation(Interval(0, 10), Interval(10, 20), IntervalRelation.Disjunct)
		self.assertIntervalRelation(Interval(10, 20), Interval(0, 10), IntervalRelation.Disjunct)

	def test_interval_relation_identical(self):
		self.assertIntervalRelation(Interval(0, 10), Interval(0, 10), IntervalRelation.Identical)
		self.assertIntervalRelation(Interval(20, 100), Interval(20, 100), IntervalRelation.Identical)

	def test_interval_relation_overlapping(self):
		self.assertIntervalRelation(Interval(0, 10), Interval(1, 11), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(1, 11), Interval(0, 10), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(5, 200), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 5), IntervalRelation.Overlapping)

		self.assertIntervalRelation(Interval(0, 10), Interval(-100, -20), IntervalRelation.Disjunct)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 0), IntervalRelation.Disjunct)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 1), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 5), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 9), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 10), IntervalRelation.Contained)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 11), IntervalRelation.Contained)
		self.assertIntervalRelation(Interval(0, 10), Interval(-100, 1000), IntervalRelation.Contained)

		self.assertIntervalRelation(Interval(0, 10), Interval(20, 100), IntervalRelation.Disjunct)
		self.assertIntervalRelation(Interval(0, 10), Interval(10, 100), IntervalRelation.Disjunct)
		self.assertIntervalRelation(Interval(0, 10), Interval(9, 100), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(5, 100), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(1, 100), IntervalRelation.Overlapping)
		self.assertIntervalRelation(Interval(0, 10), Interval(0, 100), IntervalRelation.Contained)
		self.assertIntervalRelation(Interval(0, 10), Interval(-1, 100), IntervalRelation.Contained)
		self.assertIntervalRelation(Interval(0, 10), Interval(-1000, 100), IntervalRelation.Contained)

	def test_interval_enumeration(self):
		self.assertEqual(list(Interval(0, 5).enumerate_members()), [ 0, 1, 2, 3, 4 ])
		self.assertEqual(list(Interval(-3, 3).enumerate_members()), [ -3, -2, -1, 0, 1, 2 ])

	def test_interval_relation_by_enumeration(self):
		for start1 in range(-5, 5):
			for len1 in range(1, 4):
				intvl1 = Interval(start1, start1 + len1)
				members1 = set(intvl1.enumerate_members())
				for start2 in range(-5, 5):
					for len2 in range(1, 4):
						intvl2 = Interval(start2, start2 + len2)
						members2 = set(intvl2.enumerate_members())
						intersect = members1 & members2
						if members1 == members2:
							expect_relation = IntervalRelation.Identical
						elif len(intersect) == 0:
							expect_relation = IntervalRelation.Disjunct
						elif intersect == members1:
							expect_relation = IntervalRelation.Contained
						elif intersect == members2:
							expect_relation = IntervalRelation.Container
						else:
							expect_relation = IntervalRelation.Overlapping
						self.assertIntervalRelation(intvl1, intvl2, expect_relation)

	def test_intervals_enumerate(self):
		intervals = Intervals()
		intervals.add(Interval(3, 5))
		intervals.add(Interval(0, 4))
		self.assertEqual(list(intervals.enumerate_members()), [ 0, 1, 2, 3, 3, 4 ])

	def test_intervals_interacting(self):
		intervals = Intervals()
		intervals.add(Interval(0, 4))
		intervals.add(Interval(3, 6))

		self.assertEqual(list(intervals.find_interacting(Interval(-10, -5))), [ ])
		self.assertEqual(list(intervals.find_interacting(Interval(-10, 0))), [ ])
		self.assertEqual(list(intervals.find_interacting(Interval(-10, 1))), [ intervals[0] ])
		self.assertEqual(list(intervals.find_interacting(Interval(-10, 3))), [ intervals[0] ])
		self.assertEqual(list(intervals.find_interacting(Interval(-10, 4))), [ intervals[0], intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(-10, 5))), [ intervals[0], intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(-10, 10))), [ intervals[0], intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(0, 10))), [ intervals[0], intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(1, 10))), [ intervals[0], intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(3, 10))), [ intervals[0], intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(4, 10))), [ intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(5, 10))), [ intervals[1] ])
		self.assertEqual(list(intervals.find_interacting(Interval(6, 10))), [ ])
		self.assertEqual(list(intervals.find_interacting(Interval(2, 5))), [ intervals[0], intervals[1] ])

	def test_fully_contained(self):
		intervals = Intervals()
		intervals.add(Interval(0, 4))
		intervals.add(Interval(3, 6))

		self.assertTrue(intervals.fully_contained_in_subinterval(Interval(1, 2)))
		self.assertTrue(intervals.fully_contained_in_subinterval(Interval(1, 4)))
		self.assertTrue(intervals.fully_contained_in_subinterval(Interval(0, 4)))
		self.assertTrue(intervals.fully_contained_in_subinterval(Interval(0, 3)))
		self.assertTrue(intervals.fully_contained_in_subinterval(Interval(3, 4)))
		self.assertTrue(intervals.fully_contained_in_subinterval(Interval(3, 6)))
		self.assertTrue(intervals.fully_contained_in_subinterval(Interval(4, 5)))
		self.assertFalse(intervals.fully_contained_in_subinterval(Interval(0, 10)))
		self.assertFalse(intervals.fully_contained_in_subinterval(Interval(0, 5)))
		self.assertFalse(intervals.fully_contained_in_subinterval(Interval(-1, 4)))
		self.assertFalse(intervals.fully_contained_in_subinterval(Interval(3, 1000)))
		self.assertFalse(intervals.fully_contained_in_subinterval(Interval(-100, 1000)))

	def test_no_constraints(self):
		intervals = Intervals()
		intervals.add(Interval(0, 4))
		intervals.add(Interval(0, 4))
		intervals.add(Interval(-10, 10))

	def test_no_identical_constraint(self):
		intervals = Intervals(allow_identical = False)
		intervals.add(Interval(0, 4))
		with self.assertRaises(IntervalConstraintException):
			intervals.add(Interval(0, 4))
		intervals.add(Interval(-10, 10))

	def test_no_overlapping_constraint(self):
		intervals = Intervals(allow_overlapping = False)
		intervals.add(Interval(0, 4))
		with self.assertRaises(IntervalConstraintException):
			intervals.add(Interval(0, 4))
		with self.assertRaises(IntervalConstraintException):
			intervals.add(Interval(-10, 10))
