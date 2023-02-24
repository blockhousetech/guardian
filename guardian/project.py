""" Guardian
    Copyright (C) 2021  The Blockhouse Technology Limited (TBTL)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>."""

import angr, claripy
from .tools import Default, Heuristic
from .layout import EnclaveMemoryLayout
from .plugins import EnclaveState
from .hooker import Hooker
from .breakpoints import Breakpoints
from .explorer import EnclaveExploration
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class Project:

    def __init__(self,
                 angr_project,
                 heap_size=None,
                 stack_size=None,
                 ecalls=None,
                 ocalls=None,
                 exit_addr=None,
                 enter_addr=None,
                 old_sdk=False,
                 teaclave=False,
                 find_missing_ecalls_or_ocalls=True,
                 violation_check=True):
        self.angr_project = angr_project
        self.heap_size = [
            lambda: Default().get_heap_size(), lambda: heap_size
        ][heap_size is not None]()
        self.stack_size = [
            lambda: Default().get_stack_size(), lambda: stack_size
        ][stack_size is not None]()
        self.ecalls = ecalls
        self.ocalls = ocalls
        self.exit_addr = [
            lambda: Heuristic.find_exit(self.angr_project), lambda: exit_addr
        ][exit_addr is not None]()
        self.enter_addr = [
            lambda: Heuristic.find_enter(self.angr_project), lambda: enter_addr
        ][enter_addr is not None]()
        self.old_sdk = old_sdk
        self.teaclave = teaclave
        self.find_missing_ecalls_or_ocalls = find_missing_ecalls_or_ocalls

        if self.find_missing_ecalls_or_ocalls is True:
            self.use_heurestic_for_ecalls_or_ocalls()

        self.layout = EnclaveMemoryLayout(self.angr_project, self.heap_size,
                                          self.stack_size, self.old_sdk)

        self.init_enclave_state()
        self.entry_state.register_plugin('enclave',
                                         EnclaveState(self.angr_project))
        self.entry_state.register_plugin(
            'heap',
            angr.SimHeapBrk(heap_base=self.layout.heap_start,
                            heap_size=self.layout.heap_size))
        self.entry_state.libc.max_memcpy_size = 0x100
        self.entry_state.libc.max_buffer_size = 0x100
        self.entry_state.enclave.init_trace_and_stack()

        if not self.old_sdk:
            self.entry_state.regs.d = self.entry_state.solver.BVS(
                "df", self.entry_state.arch.bits)

        self.simgr = self.angr_project.factory.simgr(self.entry_state)
        self.angr_project, self.simgr = Hooker(violation_check).setup(
            self.angr_project, self.simgr, self.ecalls, self.ocalls,
            self.exit_addr, self.enter_addr, self.old_sdk)
        # Enable violation checks if flag is set
        self.angr_project, self.simgr = Breakpoints().setup(
            self.angr_project,
            self.simgr,
            self.layout,
            violation_check=violation_check)
        self.simgr.use_technique(EnclaveExploration())

    def use_heurestic_for_ecalls_or_ocalls(self):
        if self.ecalls is None:
            self.ecalls = Heuristic.find_ecalls(self.angr_project)
        if self.ocalls is None:
            self.ocalls = [
                lambda: Heuristic.find_ocalls(self.angr_project),
                lambda: Heuristic.find_ocalls_teaclave(self.angr_project)
            ][self.teaclave is True]()

    def set_target_ecall(self, ecall_id):
        self.simgr.active[0].regs.rdi = ecall_id

    def init_enclave_state(self):
        self.entry_state = self.angr_project.factory.blank_state()
        # Set angr options to silence warnings
        self.entry_state.options.add(
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        self.entry_state.options.add(
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        # Setup entry state
        self.entry_state.regs.rip = self.angr_project.loader.find_symbol(
            "enclave_entry").rebased_addr
        self.entry_state.regs.rax = 0x0
        self.entry_state.regs.rbx = self.layout.tcs_start
        self.entry_state.regs.d = 0x0
        self.entry_state.mem[self.angr_project.loader.find_symbol(
            "g_enclave_state").rebased_addr].uint64_t = 2
        self.layout.set_global_data(self.angr_project, self.entry_state)
        self.layout.set_thread_data(self.entry_state)
