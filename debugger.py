
'''
Debugging monitor for Peach Agent.  Uses pydbgeng to monitor processes and
detect faults.  Would be nice to also eventually do other things like
"if we hit this method" or whatever.

@author: Michael Eddington
@version: $Id: debugger.py 2729 2012-02-15 00:40:49Z meddingt $
'''

#
# Copyright (c) Michael Eddington
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# Authors:
#   Michael Eddington (mike@phed.org)

# $Id: debugger.py 2729 2012-02-15 00:40:49Z meddingt $

import struct, sys, time, psutil, signal
from psutil.error import NoSuchProcess

import struct, sys, time, os, re, pickle
import gc, tempfile


try:

	import comtypes
	from ctypes import *
	from comtypes import HRESULT, COMError
	from comtypes.client import CreateObject, GetEvents, PumpEvents
	from comtypes.hresult import S_OK, E_FAIL, E_UNEXPECTED, E_INVALIDARG
	from comtypes.automation import IID
	import PyDbgEng
	from comtypes.gen import DbgEng
	import win32serviceutil
	import win32service
	import win32api, win32con, win32process, win32pdh
	from multiprocessing import *


	# ###############################################################################################
	# ###############################################################################################
	# ###############################################################################################
	# ###############################################################################################

	class _DbgEventHandler(PyDbgEng.IDebugOutputCallbacksSink, PyDbgEng.IDebugEventCallbacksSink):

		buff = ''
		TakeStackTrace = True

		def LocateWinDbg(self):
			'''
			This method also exists in process.PageHeap!
			'''

			try:

				hkey = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, "Software\\Microsoft\\DebuggingTools")

			except:

				# Lets try a few common places before failing.
				pgPaths = [
					"c:\\",
					os.environ["SystemDrive"]+"\\",
					os.environ["ProgramFiles"],
					]
				if "ProgramW6432" in os.environ:
					pgPaths.append(os.environ["ProgramW6432"])
				if "ProgramFiles(x86)" in os.environ:
					pgPaths.append(os.environ["ProgramFiles(x86)"])

				dbgPaths = [
					"Debuggers",
					"Debugger",
					"Debugging Tools for Windows",
					"Debugging Tools for Windows (x64)",
					"Debugging Tools for Windows (x86)",
					]

				for p in pgPaths:
					for d in dbgPaths:
						testPath = os.path.join(p,d)

						if os.path.exists(testPath):
							return testPath

				return None

			val, type = win32api.RegQueryValueEx(hkey, "WinDbg")
			win32api.RegCloseKey(hkey)
			return val

		def Output(self, this, Mask, Text):
			self.buff += Text

		def LoadModule(self, unknown, imageFileHandle, baseOffset, moduleSize, moduleName, imageName, checkSum, timeDateStamp = None):
			if self.pid == None:
				self.dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT,
										   c_char_p("|."),
										   DbgEng.DEBUG_EXECUTE_ECHO)

				match = re.search(r"\.\s+\d+\s+id:\s+([0-9a-fA-F]+)\s+\w+\s+name:\s", self.buff)
				if match != None:
					self.pid = int(match.group(1), 16)

					# Write out PID for main peach process
					fd = open(self.TempfilePid, "wb+")
					fd.write(str(self.pid))
					fd.close()

		def GetInterestMask(self):
			return PyDbgEng.DbgEng.DEBUG_EVENT_EXCEPTION | PyDbgEng.DbgEng.DEBUG_FILTER_INITIAL_BREAKPOINT | \
				PyDbgEng.DbgEng.DEBUG_EVENT_EXIT_PROCESS | PyDbgEng.DbgEng.DEBUG_EVENT_LOAD_MODULE

		def ExitProcess(self, dbg, ExitCode):
			#print "_DbgEventHandler.ExitProcess: Target application has exitted"
			self.quit.set()
			return DEBUG_STATUS_NO_CHANGE

		def Exception(self, dbg, ExceptionCode, ExceptionFlags, ExceptionRecord,
				ExceptionAddress, NumberParameters, ExceptionInformation0, ExceptionInformation1,
				ExceptionInformation2, ExceptionInformation3, ExceptionInformation4,
				ExceptionInformation5, ExceptionInformation6, ExceptionInformation7,
				ExceptionInformation8, ExceptionInformation9, ExceptionInformation10,
				ExceptionInformation11, ExceptionInformation12, ExceptionInformation13,
				ExceptionInformation14, FirstChance):

			if self.IgnoreSecondChanceGardPage and ExceptionCode == 0x80000001:
				return DbgEng.DEBUG_STATUS_NO_CHANGE

			# Only capture dangerouse first chance exceptions
			if FirstChance:
				if self.IgnoreFirstChanceGardPage and ExceptionCode == 0x80000001:
					# Ignore, sometimes used as anti-debugger
					# by Adobe Flash.
					return DbgEng.DEBUG_STATUS_NO_CHANGE

				# Guard page or illegal op
				elif ExceptionCode == 0x80000001 or ExceptionCode == 0xC000001D:
					pass
				elif ExceptionCode == 0xC0000005:
					# is av on eip?
					if ExceptionInformation0 == 0 and ExceptionInformation1 == ExceptionAddress:
						pass

					# is write a/v?
					elif ExceptionInformation0 == 1 and ExceptionInformation1 != 0:
						pass

					# is DEP?
					elif ExceptionInformation0 == 0:
						pass

					else:
						# Otherwise skip first chance
						return DbgEng.DEBUG_STATUS_NO_CHANGE
				else:
					# otherwise skip first chance
					return DbgEng.DEBUG_STATUS_NO_CHANGE


			if self.handlingFault.is_set() or self.handledFault.is_set():
				# We are already handling, so skip
				#sys.stdout.write("_DbgEventHandler::Exception(): handlingFault set, skipping.\n")
				return DbgEng.DEBUG_STATUS_BREAK

			try:
				#print "Exception: Found interesting exception"

				self.crashInfo = {}
				self.handlingFault.set()

				## 1. Output registers
				#print "Exception: 1. Output registers"

				dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT,
										   c_char_p("r"),
										   DbgEng.DEBUG_EXECUTE_ECHO)
				dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT,
										   c_char_p("rF"),
										   DbgEng.DEBUG_EXECUTE_ECHO)
				dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT,
										   c_char_p("rX"),
										   DbgEng.DEBUG_EXECUTE_ECHO)
				self.buff += "\n\n"

				## 2. Ouput stack trace
				if _DbgEventHandler.TakeStackTrace:
					#print "Exception: 2. Output stack trace"

					dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT,
											   c_char_p("kb"),
											   DbgEng.DEBUG_EXECUTE_ECHO)
					self.buff += "\n\n"

				else:
					_DbgEventHandler.TakeStackTrace = True
					self.buff += "\n[Peach] Error, stack trace failed.\n\n"

				## 3. Write dump file
				minidump = None

				## 4. Bang-Exploitable
				#print "Exception: 3. Bang-Expoitable"

				handle = None
				try:
					p = None
					if not (hasattr(sys,"frozen") and sys.frozen == "console_exe"):
						#p = __file__[:-24] + "tools\\bangexploitable\\"
						p = os.getcwd()+ "\\exploitable\\"
						if sys.version.find("AMD64") != -1:
							p += "x64"
						else:
							p += "x86"

					else:
						p = os.path.dirname(os.path.abspath(sys.executable))

					dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT, c_char_p(".load %s\\msec.dll" % p), DbgEng.DEBUG_EXECUTE_ECHO)
					dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT, c_char_p("!exploitable -m"), DbgEng.DEBUG_EXECUTE_ECHO)
					dbg.idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT, c_char_p("!msec.exploitable -m"), DbgEng.DEBUG_EXECUTE_ECHO)

				except:
					raise

				## Now off to other things...
				#print "Exception: Building crashInfo"

				if minidump:
					self.crashInfo = { 'StackTrace.txt' : self.buff.replace(chr(0x0a), "\r\n"), 'Dump.dmp' : minidump }
				else:
					self.crashInfo = { 'StackTrace.txt' : self.buff.replace(chr(0x0a), "\r\n") }

				# Build bucket string
				try:
					bucketId = re.compile("DEFAULT_BUCKET_ID:\s+([A-Za-z_]+)").search(self.buff).group(1)
					exceptionAddress = re.compile("ExceptionAddress: ([^\s\b]+)").search(self.buff).group(1)
					exceptionCode = re.compile("ExceptionCode: ([^\s\b]+)").search(self.buff).group(1)

					exceptionType = "AV"
					if re.compile("READ_ADDRESS").search(self.buff) != None:
						exceptionType = "ReadAV"
					elif re.compile("WRITE_ADDRESS").search(self.buff) != None:
						exceptionType = "WriteAV"

					bucket = "%s_at_%s" % (exceptionType, exceptionAddress)

				except:
					# Sometimes !analyze -v fails
					bucket = "Unknown"

				self.crashInfo["Bucket"] = bucket

				## Do we have !exploitable?

				try:
					majorHash = re.compile("^MAJOR_HASH:(0x.*)$", re.M).search(self.buff).group(1)
					minorHash = re.compile("^MINOR_HASH:(0x.*)$", re.M).search(self.buff).group(1)
					classification = re.compile("^CLASSIFICATION:(.*)$", re.M).search(self.buff).group(1)
					shortDescription = re.compile("^SHORT_DESCRIPTION:(.*)$", re.M).search(self.buff).group(1)

					if majorHash != None and minorHash != None:

						bucket = "%s_%s_%s_%s" % (classification,
							shortDescription,
							majorHash,
							minorHash)

						self.crashInfo["Bucket"] = bucket

				except:
					pass

				# Done

			except:
				sys.stdout.write(repr(sys.exc_info()) + "\n")
				raise

			self.buff = ""
			self.fault = True

			#print "Exception: Writing to file"
			fd = open(self.Tempfile, "wb+")
			#fd = open("log.txt", "wb+")
			fd.write(pickle.dumps(self.crashInfo))
			fd.close()

			self.handledFault.set()
			return DbgEng.DEBUG_STATUS_BREAK


	def WindowsDebugEngineProcess_run(*args, **kwargs):

		started = kwargs['Started']
		handlingFault = kwargs['HandlingFault']
		handledFault = kwargs['HandledFault']
		CommandLine = kwargs.get('CommandLine', None)
		Service = kwargs.get('Service', None)
		ProcessName = kwargs.get('ProcessName', None)
		ProcessID = kwargs.get('ProcessID', None)
		KernelConnectionString = kwargs.get('KernelConnectionString', None)
		SymbolsPath = kwargs.get('SymbolsPath', None)
		IgnoreFirstChanceGardPage = kwargs.get('IgnoreFirstChanceGardPage', None)
		IgnoreSecondChanceGardPage = kwargs.get('IgnoreSecondChanceGardPage', None)
		quit = kwargs['Quit']
		Tempfile = kwargs['Tempfile']
		WinDbg = kwargs['WinDbg']
		TempfilePid = kwargs['TempfilePid']
		FaultOnEarlyExit = kwargs['FaultOnEarlyExit']

		dbg = None

		#print "WindowsDebugEngineProcess_run"

		# Hack for comtypes early version
		comtypes._ole32.CoInitializeEx(None, comtypes.COINIT_APARTMENTTHREADED)

		try:
			_eventHandler = _DbgEventHandler()
			_eventHandler.pid = None
			_eventHandler.handlingFault = handlingFault
			_eventHandler.handledFault = handledFault
			_eventHandler.IgnoreFirstChanceGardPage = IgnoreFirstChanceGardPage
			_eventHandler.IgnoreSecondChanceGardPage = IgnoreSecondChanceGardPage
			_eventHandler.quit = quit
			_eventHandler.Tempfile = Tempfile
			_eventHandler.TempfilePid = TempfilePid
			_eventHandler.FaultOnEarlyExit = FaultOnEarlyExit

			if KernelConnectionString:
				dbg = PyDbgEng.KernelAttacher(  connection_string = KernelConnectionString,
					event_callbacks_sink = _eventHandler,
					output_callbacks_sink = _eventHandler,
					symbols_path = SymbolsPath,
					dbg_eng_dll_path = WinDbg)

			elif CommandLine:
				dbg = PyDbgEng.ProcessCreator(command_line = CommandLine,
					follow_forks = True,
					event_callbacks_sink = _eventHandler,
					output_callbacks_sink = _eventHandler,
					symbols_path = SymbolsPath,
					dbg_eng_dll_path = WinDbg)

			elif ProcessName:

				pid = None
				for x in range(10):
					print "WindowsDebugEngineThread: Attempting to locate process by name..."
					pid = GetProcessIdByName(ProcessName)
					if pid != None:
						break

					time.sleep(0.25)

				if pid == None:
					raise Exception("Error, unable to locate process '%s'" % ProcessName)

				dbg = PyDbgEng.ProcessAttacher(pid,
					event_callbacks_sink = _eventHandler,
					output_callbacks_sink = _eventHandler,
					symbols_path = SymbolsPath,
					dbg_eng_dll_path = WinDbg)

			elif ProcessID:

				print "Attaching by pid:", ProcessID
				pid = ProcessID
				dbg = PyDbgEng.ProcessAttacher(pid,	event_callbacks_sink = _eventHandler,
					output_callbacks_sink = _eventHandler, symbols_path = SymbolsPath,
					dbg_eng_dll_path = WinDbg)

			elif Service:

				# Make sure service is running
				if win32serviceutil.QueryServiceStatus(Service)[1] != 4:
					try:
						# Some services auto-restart, if they do
						# this call will fail.
						win32serviceutil.StartService(Service)
					except:
						pass

					while win32serviceutil.QueryServiceStatus(Service)[1] == 2:
						time.sleep(0.25)

					if win32serviceutil.QueryServiceStatus(Service)[1] != 4:
						raise Exception("WindowsDebugEngine: Unable to start service!")

				# Determin PID of service
				scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
				hservice = win32service.OpenService(scm, Service, 0xF01FF)

				status = win32service.QueryServiceStatusEx(hservice)
				pid = status["ProcessId"]

				win32service.CloseServiceHandle(hservice)
				win32service.CloseServiceHandle(scm)

				dbg = PyDbgEng.ProcessAttacher(pid,
					event_callbacks_sink = _eventHandler,
					output_callbacks_sink = _eventHandler,
					symbols_path = SymbolsPath,
					dbg_eng_dll_path = WinDbg)

			else:
				raise Exception("Didn't find way to start debugger... bye bye!!")

			_eventHandler.dbg = dbg
			started.set()
			dbg.event_loop_with_quit_event(quit)

		finally:
			if dbg != None:
				if dbg.idebug_client != None:
					dbg.idebug_client.EndSession(DbgEng.DEBUG_END_ACTIVE_TERMINATE)
					dbg.idebug_client.Release()
				elif dbg.idebug_control != None:
					dbg.idebug_control.EndSession(DbgEng.DEBUG_END_ACTIVE_TERMINATE)
					dbg.idebug_control.Release()

			dbg = None

			comtypes._ole32.CoUninitialize()


	def GetProcessIdByName(procname):
		'''
		Try and get pid for a process by name.
		'''

		ourPid = -1
		procname = procname.lower()

		try:
			ourPid = win32api.GetCurrentProcessId()

		except:
			pass

		pids = win32process.EnumProcesses()
		for pid in pids:
			if ourPid == pid:
				continue

			try:
				hPid = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 0, pid)

				try:
					mids = win32process.EnumProcessModules(hPid)
					for mid in mids:
						name = str(win32process.GetModuleFileNameEx(hPid, mid))
						if name.lower().find(procname) != -1:
							return pid

				finally:
					win32api.CloseHandle(hPid)
			except:
				pass

		return None

	class Monitor:
		'''
		Extend from this to implement a Monitor.  Monitors are
		run by an Agent and must operate in an async mannor.  Any
		blocking tasks must be performed in another thread.
		'''

		def __init__(self, args):
			'''
			Constructor.  Arguments are supplied via the Peach XML
			file.

			@type	args: Dictionary
			@param	args: Dictionary of parameters
			'''

			# Our name for this monitor
			self._name = None

		def OnTestStarting(self):
			'''
			Called right before start of test case or variation
			'''
			pass

		def OnTestFinished(self):
			'''
			Called right after a test case or varation
			'''
			pass

		def GetMonitorData(self):
			'''
			Get any monitored data from a test case.
			'''
			return None

		def RedoTest(self):
			'''
			Should the current test be reperformed.
			'''
			return False

		def DetectedFault(self):
			'''
			Check if a fault was detected.
			'''
			return False

		def OnFault(self):
			'''
			Called when a fault was detected.
			'''
			pass

		def OnShutdown(self):
			'''
			Called when Agent is shutting down, typically at end
			of a test run or when a Stop-Run occurs
			'''
			pass

		def StopRun(self):
			'''
			Return True to force test run to fail.  This
			should return True if an unrecoverable error
			occurs.
			'''
			return False

		def PublisherCall(self, method):
			'''
			Called when a call action is being performed.  Call
			actions are used to launch programs, this gives the
			monitor a chance to determin if it should be running
			the program under a debugger instead.

			Note: This is a bit of a hack to get this working
			'''
			pass


# Need to define Monitor before we do this include!
	class WindowsDebugEngine(Monitor):
		'''
		Windows debugger agent.  This debugger agent is based on the windbg engine and
		supports the following features:

			* User mode debugging
			* Kernel mode debugging
			* x86 and x64
			* Symbols and symbol server

		'''
		def __init__(self, args):
			Monitor.__init__(self, args)

			#print "WindowsDebugEngine::__init__()"

			self.started = None
			# Set at start of exception handling
			self.handlingFault = None
			# Set when collection finished
			self.handledFault = None
			self.crashInfo = None
			self.fault = False
			self.thread = None
			self.tempfile = None
			self.WinDbg = None
			self.CommandLine = args
			self.Service = None
			self.ProcessName = None

			self.ProcessID = None


			self.KernelConnectionString = None

			self.SymbolsPath = "SRV*http://msdl.microsoft.com/download/symbols"
			self.StartOnCall = False


			self.IgnoreFirstChanceGardPage = False


			self.IgnoreSecondChanceGardPage = False
			self.NoCpuKill = False
			self.FaultOnEarlyExit = False
			self.TimeOut = 1.5
			if self.Service == None and self.CommandLine == None and self.ProcessName == None \
					and self.KernelConnectionString == None and self.ProcessID == None:
				raise PeachException("Unable to create WindowsDebugEngine, missing Service, or CommandLine, or ProcessName, or ProcessID, or KernelConnectionString parameter.")

			self.handlingFault = None
			self.handledFault = None
		def _SetTimeOut(self, t):
			self.TimeOut = t
		def _StartDebugger(self):

			try:
				if self.cpu_hq != None:
					win32pdh.RemoveCounter(self.cpu_counter_handle)
					win32pdh.CloseQuery(self.cpu_hq)
					self.cpu_hq = None
					self.cpu_counter_handle = None
			except:
				pass

			# Clear all our event handlers
			self.started = Event()
			self.quit = Event()
			self.handlingFault = Event()
			self.handledFault = Event()
			self.crashInfo = None
			self.fault = False
			self.pid = None
			self.cpu_process = None
			self.cpu_path = None
			self.cpu_hq = None
			self.cpu_counter_handle = None

			#(fd, self.tempfile) = tempfile.mkstemp()
			#print self.tempfile
			self.tempfile = "debugger.TMP"
			#os.close(fd)
			#with open(self.tempfile, "rb+") as f:
			#	print "succeed"\
			self.tempfilepid = "debugger.TMPPID"
			#(fd, self.tempfilepid) = tempfile.mkstemp()
			#os.close(fd)

			self.thread = Process(group = None, target = WindowsDebugEngineProcess_run, kwargs = {
				'Started':self.started,
				'HandlingFault':self.handlingFault,
				'HandledFault':self.handledFault,
				'CommandLine':self.CommandLine,
				'Service':self.Service,
				'ProcessName':self.ProcessName,
				'ProcessID':self.ProcessID,
				'KernelConnectionString':self.KernelConnectionString,
				'SymbolsPath':self.SymbolsPath,
				'IgnoreFirstChanceGardPage':self.IgnoreFirstChanceGardPage,
				'IgnoreSecondChanceGardPage':self.IgnoreSecondChanceGardPage,
				'Quit':self.quit,
				'Tempfile':self.tempfile,
				'WinDbg':self.WinDbg,
				'TempfilePid':self.tempfilepid,
				'FaultOnEarlyExit':self.FaultOnEarlyExit
				})

			# Kick off our thread:
			self.thread.start()

			# Wait it...!
			self.started.wait()

			if(self.TimeOut == -1):
				while True:
					if self.DetectedFault() or self.quit.is_set():
						return

					time.sleep(0.1)

			if not self.NoCpuKill:
				# Make sure we wait at least 1 second
				# for program to startup.  Needed with new
				# CPU killing k0de.
				time.sleep(self.TimeOut)

		def _StopDebugger(self, force = False):

			if force == False and self.handledFault != None and (self.handlingFault.is_set() and not self.handledFault.is_set()):
				print "_StopDebugger(): Not killing process due to fault handling"
				return

			#print "_StopDebugger() - force:", force

			if self.thread != None and self.thread.is_alive():
				self.quit.set()
				self.started.clear()

				self.thread.join(5)

				if force == False and self.handledFault != None and (self.handlingFault.is_set() and not self.handledFault.is_set()):
					print "_StopDebugger(): Not killing process due to fault handling - 2"
					return

				if self.thread.is_alive():

					# 1. Terminate child process
					if self.pid != None:
						psutil.Process(self.pid).terminate()

					# 2. Terminate debugger process
					self.thread.terminate()

					# 3. Join process to avoid ZOMBIES!
					self.thread.join()

				time.sleep(0.25) # Take a breath

			elif self.thread != None:
				# quit could be set by event handler now
				self.thread.join()

			self.thread = None

		def _IsDebuggerAlive(self):
			return self.thread and self.thread.is_alive()

		def OnTestStarting(self):
			'''
			Called right before start of test.
			'''

			if not self.StartOnCall and not self._IsDebuggerAlive():
				self._StartDebugger()
			elif self.StartOnCall:
				self._StopDebugger()

		def PublisherCall(self, method):

			if not self.StartOnCall:
				return None

			if self.OnCallMethod == method.lower():
				self._StartDebugger()
				return True

			if self.OnCallMethod+"_isrunning" == method.lower():

				# Program has stopped if we are handling a fault.
				if self.handlingFault.is_set() or self.handledFault.is_set():
					return False

				if not self.quit.is_set():
					if self.pid == None:
						fd = open(self.tempfilepid, "rb+")
						pid = fd.read()
						fd.close()

						if len(pid) != 0:
							self.pid = int(pid)

							try:
								os.unlink(self.tempfilepid)
							except:
								pass

					if self.NoCpuKill == False and self.pid != None:
						try:
							# Check and see if the CPU utalization is low
							cpu = psutil.Process(self.pid).get_cpu_percent(interval=1.0)
							if cpu != None and cpu < 1.0:
								cpu = psutil.Process(self.pid).get_cpu_percent(interval=1.0)
								if cpu != None and cpu < 1.0 and not self.quit.is_set():
									print "PublisherCall: Stopping debugger, CPU:", cpu
									self._StopDebugger()
									return False

						except NoSuchProcess, e:
							pass

				return not self.quit.is_set()

			return None

		def OnTestFinished(self):
			if not self.StartOnCall or not self._IsDebuggerAlive():
				return

			self._StopDebugger()

		def GetMonitorData(self):
			'''
			Get any monitored data.
			'''
			#print "GetMonitorData(): Loading from file"
			#print os.path.exists(self.tempfile)
			#print self.tempfile
			#print os.getcwd()
			fd = open(self.tempfile, "rb")
			self.crashInfo = pickle.loads(fd.read())
			fd.close()
			
			try:
				os.remove(self.tempfile)
			except:
				pass

			#print "GetMonitorData(): Got it!"
			if self.crashInfo != None:
				ret = self.crashInfo
				self.crashInfo = None
				return ret

			return None

		def RedoTest(self):
			'''
			Returns True if the current iteration should be repeated
			'''

			if self.handlingFault == None:
				return False

			if self.thread and self.thread.is_alive():
				time.sleep(0.15)

			if not self.handlingFault.is_set():
				return False

			print "RedoTest: Waiting for self.handledFault..."

			t = 60.0 * 3
			self.handledFault.wait(timeout=t)

			if not self.handledFault.is_set():
				print "RedoTest: Timmed out waiting for fault information"
				print "RedoTest: Killing debugger and target"
				self._StopDebugger(True)
				_DbgEventHandler.TakeStackTrace = False
				print "RedoTest: Attempting to re-run iteration"
				return True

			return False

		def DetectedFault(self):
			'''
			Check if a fault was detected.
			'''

			if self.FaultOnEarlyExit and (self.thread == None or not self.thread.is_alive()) and \
				(self.handledFault == None or not self.handledFault.is_set()):

				print ">>>>>> RETURNING EARLY EXIT FAULT <<<<<<<<<"
				return True

			if self.handlingFault == None:
				print "DetectedFault: Agent was re-set, returning false"
				return False

			if self.thread and self.thread.is_alive():
				time.sleep(0.15)

			if not self.handlingFault.is_set():
				return False

			#print ">>>>>> RETURNING FAULT <<<<<<<<<"

			return True

		def OnFault(self):
			'''
			Called when a fault was detected.
			'''
			self._StopDebugger()

		def OnShutdown(self):
			'''
			Called when Agent is shutting down.
			'''
			self._StopDebugger()

	class DebuggerMonitor:
	    def __init__(self, commandline, faultPath):
	        self._debugger = WindowsDebugEngine(commandline)
	        self._count = 0
	        self._logPath = ''
	        self._faultPath = faultPath
	        self._timeout = 1.5
	        self._faultDetected = False

	    def setTimeOut(self, t):
	    	self._timeout = t
	    	self._debugger._SetTimeOut(t)
	    def get_log_dir(self):
	    	return self._logPath
	    def __del__(self):
	    	self._debugger._StopDebugger()
	    def run(self):
	        self._faultDetected = False
	        self._debugger._StartDebugger()
	        if self._debugger.DetectedFault():
	            self._faultDetected = True
	            print ">>>>>>>>>>>FAULT DETECTED<<<<<<<<<<"
	            monitorData = self._debugger.GetMonitorData()
	            bucketInfo = None
	            #print monitorData.keys()
	            for key in monitorData.keys():
	                if key.find("Bucket") > -1:
	                    bucketInfo = monitorData[key]
	                    break
	            #path = os.path.join(path, "Faults")

	            try:
	                os.mkdir(self._faultPath)
	            except:
	                pass

	            if bucketInfo != None:
	                #print "BucketInfo:", bucketInfo

	                bucketInfos = bucketInfo.split(os.path.sep)
	                path = self._faultPath
	                for p in bucketInfos:
	                    path = os.path.join(path,p)
	                    try:
	                        os.mkdir(path)
	                    except:
	                        pass


	                newPath = os.path.join(path,str(self._count))
	                while os.path.exists(newPath):
	                    self._count += 1
	                    newPath = os.path.join(path,str(self._count))
	                try:
	                    os.mkdir(newPath)
	                    self._count += 1
	                except:
	                    pass
	                path = newPath
	                self._logPath = path
	            else:
	                try:
	                    path = os.path.join(self.faultPath,"Unknown")
	                    os.mkdir(path)
	                except:
	                    pass

	                path = os.path.join(self.faultPath,"Unknown",str(variationCount))

	            for key in monitorData.keys():
	                if key.find("Bucket") == -1:
	                    fout = open(os.path.join(path,key), "wb")
	                    fout.write(monitorData[key])
	                    fout.close()

	        self._debugger._StopDebugger()

except Exception, e:
	# Only complain on Windows platforms.
	#if sys.platform == 'win32':
	#	print "Warning: Windows debugger failed to load: ", sys.exc_info()
	print e
	pass


if __name__ == "__main__":
	dbg = DebuggerMonitor("crashtest.exe", "log")
	dbg.setTimeOut(-1)
	dbg.run()
	logdir =  dbg.get_log_dir()

	print "#Iteration Finished"
	#del(dbg)