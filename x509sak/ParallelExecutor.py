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

import enum
import queue
import multiprocessing

class ParallelExecutor():
	class Signal(enum.IntEnum):
		Work = 1
		Result = 2
		Terminate = 3
		WorkerTerminated = 4

	def __init__(self, work_generator, worker_function, result_processing_function, process_count = None, queue_size = None):
		self._work_generator = work_generator
		self._worker_function = worker_function
		self._result_processing_function = result_processing_function
		self._process_count = process_count
		if self._process_count is None:
			self._process_count = multiprocessing.cpu_count()
		self._queue_size = queue_size or self._process_count
		self._work_queue = None
		self._result_queue = None
		self._mode = None

	def _kill_workers(self):
		for i in range(self._process_count):
			self._work_queue.put((self.Signal.Terminate, None))

	def _worker_trampoline(self):
		try:
			while self._mode == "run":
				(queue_signal, work_item) = self._work_queue.get()
				if queue_signal == self.Signal.Terminate:
					self._result_queue.put((self.Signal.WorkerTerminated, None))
					break
				result = self._worker_function(work_item)
				self._result_queue.put((self.Signal.Result, result))
		except KeyboardInterrupt:
			self._mode = "interrupt"

	def _generator_trampoline(self):
		try:
			for work_item in self._work_generator():
				if self._mode != "run":
					break
				self._work_queue.put((self.Signal.Work, work_item))
			self._kill_workers()
		except KeyboardInterrupt:
			# Empty work queue
			try:
				while True:
					self._work_queue.get(timeout = 0)
			except queue.Empty:
				pass
			self._mode = "interrupt"

	def _process_results(self):
		terminated_workers = 0
		try:
			while self._mode == "run":
				(queue_signal, result_item) = self._result_queue.get()
				if queue_signal == self.Signal.Terminate:
					break
				elif queue_signal == self.Signal.WorkerTerminated:
					terminated_workers += 1
					if terminated_workers == self._process_count:
						# All workers dead
						break
					continue
				self._result_processing_function(result_item)
		except KeyboardInterrupt:
			self._mode = "interrupt"

	def _run_single(self):
		"""Run in single-process mode, mainly for debugging."""
		for work_item in self._work_generator():
			result = self._worker_function(work_item)
			self._result_processing_function(result)

	def run(self):
		if self._process_count == 1:
			return self._run_single()

		self._work_queue = multiprocessing.Queue(maxsize = self._queue_size)
		self._result_queue = multiprocessing.Queue(maxsize = self._queue_size)
		self._mode = "run"

		try:
			workers = [ multiprocessing.Process(target = self._worker_trampoline) for i in range(self._process_count) ]
			for worker in workers:
				worker.start()

			work_generator = multiprocessing.Process(target = self._generator_trampoline)
			work_generator.start()

			self._process_results()

			work_generator.join()
			for worker in workers:
				worker.join()
		finally:
			self._kill_workers()
