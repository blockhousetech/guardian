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


class EnclaveMemoryLayout:
    # As per SDK definitions:

    SE_PAGE_SIZE = 0x1000
    SE_PAGE_SHIFT = 12
    SE_GUARD_PAGE_SIZE = 0x10000
    TCS_SIZE = SE_PAGE_SIZE
    SSA_FRAME_SIZE = 1
    SSA_NUM = 2
    TD_SIZE = 15 * 8

    def page_count_for_size(self, size):
        return size >> self.SE_PAGE_SHIFT

    def size_from_page_count(self, count):
        return count << self.SE_PAGE_SHIFT

    def round_size_for_page(self, size):
        return self.size_from_page_count(self.page_count_for_size(size))

    def round_to_page(self, size):
        return (((size) + ((self.SE_PAGE_SIZE) - 1))
                & ~((self.SE_PAGE_SIZE) - 1))

    def get_last_section(self, project):
        max_section = None
        for section in project.loader.main_object.sections:
            if max_section is None or section.max_addr > max_section.max_addr:
                max_section = section
        return max_section

    def get_base_addr(self, project):
        # We could use the following more "angr-based" solution:
        # return project.loader.main_object.mapped_base
        # but I will stick with the SGX's specific one below for the time being:
        return project.loader.find_symbol("__ImageBase").rebased_addr

    # We are only considering enclaves that do not have a dynamically-sized heap
    def __init__(self, project, heap_init_size, stack_max_size, old_sdk):
        last_section = self.get_last_section(project)
        self.old_sdk = old_sdk
        self.base_addr = self.get_base_addr(project)
        assert last_section is not None
        assert self.base_addr is not None
        self.heap_start = self.round_to_page(
            last_section.min_addr - self.base_addr +
            last_section.memsize) + self.base_addr
        self.heap_size = heap_init_size
        self.stack_start = self.heap_start + self.round_size_for_page(
            self.heap_size) + self.round_size_for_page(self.SE_GUARD_PAGE_SIZE)
        self.stack_size = stack_max_size
        self.tcs_start = self.stack_start + self.round_size_for_page(
            self.stack_size) + self.round_size_for_page(
                self.SE_GUARD_PAGE_SIZE)
        self.tcs_size = self.TCS_SIZE
        self.ssa_start = self.tcs_start + self.round_size_for_page(
            self.tcs_size)
        self.ssa_size = self.size_from_page_count(self.SSA_FRAME_SIZE *
                                                  self.SSA_NUM)
        self.td_start = self.ssa_start + self.round_size_for_page(
            self.ssa_size) + self.round_size_for_page(self.SE_GUARD_PAGE_SIZE)
        self.td_size = self.TD_SIZE
        self.enclave_size = self.td_start + self.round_size_for_page(
            self.td_size) + 1
        assert self.enclave_size > self.td_start + self.round_size_for_page(
            self.td_size)
        project.loader.memory.add_backer(
            self.heap_start,
            bytearray(self.td_start + self.round_size_for_page(self.td_size) -
                      self.heap_start))

    def set_global_data(self, project, state):
        global_data_addr = project.loader.find_symbol(
            "g_global_data").rebased_addr
        if self.old_sdk:
            # sdk version
            # state.mem[global_data_addr].uint64_t = 0
            # enclave size
            state.mem[global_data_addr + 0 * 8].uint64_t = self.enclave_size
            # heap offset
            state.mem[global_data_addr +
                      1 * 8].uint64_t = self.heap_start - self.base_addr
            #heap size
            state.mem[global_data_addr + 2 * 8].uint64_t = self.heap_size
            # thread policy
            #state.mem[global_data_addr + 7*8].uint64_t = 0
        else:
            # sdk version
            state.mem[global_data_addr].uint64_t = 0
            # enclave size
            state.mem[global_data_addr + 1 * 8].uint64_t = self.enclave_size
            # heap offset
            state.mem[global_data_addr +
                      2 * 8].uint64_t = self.heap_start - self.base_addr
            #heap size
            state.mem[global_data_addr + 3 * 8].uint64_t = self.heap_size
            # thread policy
            #state.mem[global_data_addr + 7*8].uint64_t = 0

    def set_thread_data(self, state):
        # gs and fs
        state.regs.gs = self.td_start
        state.regs.fs = self.td_start
        # self addr
        state.mem[self.td_start].uint64_t = self.td_start

        # the following values are the result of td_template and do_init_thread in
        # https://github.com/intel/linux-sgx/blob/b9b071b54476e93ba21ae4f8dc41394970667cdd/sdk/trts/trts_ecall.cpp

        # last sp relative to tcs in template but not here
        state.mem[self.td_start +
                  8].uint64_t = self.stack_start + self.round_size_for_page(
                      self.stack_size)
        # stack base relative to tcs in template but not here
        state.mem[self.td_start +
                  0x10].uint64_t = self.stack_start + self.round_size_for_page(
                      self.stack_size)
        # stack limit relative to tcs in template but not here
        state.mem[self.td_start +
                  0x18].uint64_t = self.stack_start + self.round_size_for_page(
                      self.stack_size) - self.stack_size

    def print(self):
        print("Heap start: ", hex(self.heap_start))
        print("Heap size: ", hex(self.heap_size))
        print("Stack start: ", hex(self.stack_start))
        print("Stack size: ", hex(self.stack_size))
        print("TCS start: ", hex(self.tcs_start))
        print("TCS size: ", hex(self.tcs_size))
        print("SSA start: ", hex(self.ssa_start))
        print("SSA size: ", hex(self.ssa_size))
        print("TD start: ", hex(self.td_start))
