#!/usr/bin/env python3
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

import threading

class Parallelizer(object):
	def __init__(self, parallel_tasks = None):
		self._parallel_tasks = parallel_tasks
		if self._parallel_tasks is None:
			with open("/proc/cpuinfo") as f:
				self._parallel_tasks = len(list(line for line in f.read().split("\n") if line.startswith("processor")))
		self._sem = threading.Semaphore(self._parallel_tasks)

	def _job_thread(self, job, job_args, finished_callback):
		try:
			result = job(*job_args)
		except Exception as e:
			result = e
		if finished_callback is not None:
			finished_callback(job_args, result)
		self._sem.release()

	def run(self, job, args = (), finished_callback = None):
		self._sem.acquire()
		thread = threading.Thread(target = self._job_thread, args = (job, args, finished_callback))
		thread.start()

	def wait(self):
		for i in range(self._parallel_tasks):
			self._sem.acquire()
		self._sem = threading.Semaphore(self._parallel_tasks)
