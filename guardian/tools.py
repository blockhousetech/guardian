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

import angr
import logging
import io
import copy
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from .timeout import Timeout

log = logging.getLogger(__name__)


class Default:
    heap_size = 0x100000
    stack_size = 0x40000

    def get_heap_size(self):
        return self.heap_size

    def get_stack_size(self):
        return self.stack_size


class Heuristic:

    def find_exit(proj):
        enclave_entry_symb = proj.loader.find_symbol("enclave_entry")
        do_ocall_addr = proj.loader.find_symbol("do_ocall").rebased_addr
        enclave_entry_addr = enclave_entry_symb.rebased_addr
        assert do_ocall_addr > enclave_entry_addr
        symb_bytes = proj.loader.memory.load(
            enclave_entry_addr, do_ocall_addr - enclave_entry_addr)
        exit_addr = None
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(symb_bytes, enclave_entry_addr):
            if i.mnemonic == "enclu":
                exit_addr = i.address
        assert exit_addr is not None
        return exit_addr

    def find_enter(proj):
        enclave_entry_symb = proj.loader.find_symbol("enclave_entry")
        do_ocall_addr = proj.loader.find_symbol("do_ocall").rebased_addr
        enter_enclave_addr = proj.loader.find_symbol(
            "enter_enclave").rebased_addr
        enclave_entry_addr = enclave_entry_symb.rebased_addr
        assert do_ocall_addr > enclave_entry_addr
        symb_bytes = proj.loader.memory.load(
            enclave_entry_addr, do_ocall_addr - enclave_entry_addr)
        enter_addr = None
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(symb_bytes, enclave_entry_addr):
            if i.mnemonic == "call" and i.op_str == hex(enter_enclave_addr):
                enter_addr = i.address
                break
        assert enter_addr is not None
        return enter_addr

    def find_ocalls(proj):
        ocalloc_address = proj.loader.find_symbol("sgx_ocall").rebased_addr
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        ocalls = []
        for symb in proj.loader.symbols:
            if symb.is_function:
                symb_addr = symb.rebased_addr
                symb_bytes = proj.loader.memory.load(symb_addr, symb.size)
                is_ocall = False
                ocall_rets = []
                sgx_ocalls = []
                for i in md.disasm(symb_bytes, symb_addr):
                    if i.mnemonic == "call" and i.op_str == hex(
                            ocalloc_address):
                        sgx_ocalls.append(i.address)
                if len(sgx_ocalls) > 0:
                    for i in md.disasm(symb_bytes, symb_addr):
                        if i.mnemonic == "ret":
                            ocall_rets.append(i.address)

                    assert len(ocall_rets) > 0
                    ocalls.append(
                        (symb.name, symb_addr, sgx_ocalls, ocall_rets))

        return ocalls

    def find_ocalls_teaclave(proj):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        ocalls = []
        for symb in proj.loader.symbols:
            is_ocall = "ocall" in symb.name and "libc" in symb.name
            if is_ocall:
                if symb.is_function:
                    symb_addr = symb.rebased_addr
                    symb_bytes = proj.loader.memory.load(symb_addr, symb.size)
                    ocall_rets = []
                    for i in md.disasm(symb_bytes, symb_addr):
                        if i.mnemonic == "ret":
                            ocall_rets.append(i.address)

                    assert len(ocall_rets) > 0
                    ocalls.append((symb.name, symb_addr, [], ocall_rets))

        return ocalls

    def find_ocalls_silly(proj):
        ocalls = []
        for symb in proj.loader.symbols:
            if symb.is_function:
                if "ocall" in symb.name:
                    ocalls.append((symb.name, symb.rebased_addr))
        return ocalls

    def find_ecalls_silly(proj):
        ecalls = []
        for symb in proj.loader.symbols:
            if symb.is_function:
                if "ecall" in symb.name:
                    ecalls.append((symb.name, symb.rebased_addr))
        return ecalls

    def find_ecalls(proj):
        ecall_table = proj.loader.find_symbol("g_ecall_table")
        ecall_table_bytes = proj.loader.memory.load(ecall_table.rebased_addr,
                                                    ecall_table.size)
        num_ecalls = int.from_bytes(ecall_table_bytes[0:8], "little")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        ecalls = []
        non_ecalls = {hex(proj.loader.find_symbol(symb_name).rebased_addr) for symb_name in \
            ["dlmalloc", "dlfree", "memcpy", "calloc", "memset", "memcpy_s", "memset_s", "sgx_is_within_enclave", "sgx_is_outside_enclave", "strlen", "abort"] if proj.loader.find_symbol(symb_name) is not None}
        for index in range(num_ecalls):
            ecall_info_index = 8 + index * 16
            ecall_addr = int.from_bytes(
                ecall_table_bytes[ecall_info_index:ecall_info_index + 8],
                "little")
            ecall_is_priv = int.from_bytes(
                ecall_table_bytes[ecall_info_index + 8:ecall_info_index + 9],
                "little")
            ecall_is_switchless = int.from_bytes(
                ecall_table_bytes[ecall_info_index + 9:ecall_info_index + 10],
                "little")

            ecall_symb = proj.loader.find_symbol(ecall_addr)
            symb_bytes = proj.loader.memory.load(ecall_addr, ecall_symb.size)
            ecall_rets = []
            for i in md.disasm(symb_bytes, ecall_addr):
                if i.mnemonic == "call" and i.op_str not in non_ecalls:
                    ecall_rets.append((i.address, i.address + i.size))

            assert len(ecall_rets) > 0
            ecalls.append((index, ecall_symb.name, ecall_addr, ecall_rets))

        return ecalls

    def find_ecalls_parameters(proj, ecalls):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        ecalls_info = []
        for (ecall_index, ecall_name, ecall_addr, ecall_rets) in ecalls:
            symb = proj.loader.find_symbol(ecall_addr)
            symb_bytes = proj.loader.memory.load(ecall_addr, symb.size)

            # Find ms structure size
            ms_size = None
            ms_vars = None

            for i in md.disasm(symb_bytes, ecall_addr):
                if i.bytes[0:1] == b"\xbe" and i.size == 5:
                    ms_size = int.from_bytes(i.bytes[1:5], "little")
                    break

            if ms_size is not None:
                ms_vars = {}
                for i in md.disasm(symb_bytes, ecall_addr):
                    if i.mnemonic == "mov":
                        lhs, rhs = i.op_str.split(",", 1)
                        if is_var_access(lhs):
                            ms_vars[get_offset(lhs)] = get_size(lhs)
                        elif is_var_access(rhs):
                            ms_vars[get_offset(rhs)] = get_size(rhs)

            ecalls_info.append((ecall_index, ecall_name, ecall_addr,
                                ecall_rets, ms_size, ms_vars))

        return ecalls_info

    class Helper:

        def is_var_access(op_str):
            return "ptr [rax" in op_str or "ptr [rbx" in op_str

        def get_size(op_str):
            size_str = op_str[:op_str.find("[")].strip()
            if size_str == "byte ptr":
                return 1
            elif size_str == "word ptr":
                return 2
            elif size_str == "dword ptr":
                return 4
            elif size_str == "qword ptr":
                return 8

        def get_offset(op_str):
            addr_str = op_str[op_str.find("[") + 1:op_str.find("]")]
            try:
                _, offset_str = addr_str.split("+")
            except:
                return 0

            try:
                return int(offset_str, 0)
            except:
                pass


class Report:

    def __init__(self, guardian_project, timeout):
        self.guardian_project = guardian_project
        self.timeout = timeout
        self.report = None
        plugins_log = logging.getLogger("guardian.plugins")

        previous_logging_level = log.getEffectiveLevel()
        previous_plugins_logging_level = plugins_log.getEffectiveLevel()
        log.setLevel(logging.INFO)
        plugins_log.setLevel(logging.INFO)
        stream_object = io.StringIO()
        stream_handler = logging.StreamHandler(stream_object)
        stream_handler.setLevel(logging.INFO)
        log.addHandler(stream_handler)
        plugins_log.addHandler(stream_handler)

        log.info("There are {} ecalls to analyse.\n".format(
            len(self.guardian_project.ecalls)))
        for (ecall_index, ecall_name, ecall_addr,
             _) in guardian_project.ecalls:
            self.analyse_ecall(ecall_index, ecall_name, ecall_addr)

        log_contents = stream_object.getvalue()
        self.report = log_contents
        log.removeHandler(stream_handler)
        plugins_log.removeHandler(stream_handler)
        stream_object.close()
        log.setLevel(previous_logging_level)
        plugins_log.setLevel(previous_plugins_logging_level)

    def save(self, file):
        file.write(self.report)

    def analyse_ecall(self,
                      ecall_index,
                      ecall_name=None,
                      ecall_addr=None,
                      debug=False):
        assert self.timeout >= 0

        if ecall_addr == None or ecall_name == None:
            [(_, ecall_name, ecall_addr, _)
             ] = [e for e in ecalls if e[0] == ecall_index]

        # Instead of doing a deep copy, we will create a minimal guardian project.
        # It is customary but not required to place all import statements at the beginning of a module (Python documentation 6.1)
        # We violate this custom here...
        from .project import Project
        proj = angr.Project(self.guardian_project.angr_project.filename)
        guard = Project(proj,
                        find_missing_ecalls_or_ocalls=False,
                        old_sdk=self.guardian_project.old_sdk,
                        teaclave=self.guardian_project.teaclave,
                        ecalls=self.guardian_project.ecalls,
                        ocalls=self.guardian_project.ocalls)
        guard.set_target_ecall(ecall_index)

        log.info("Analysing ecall: {} {}...".format(ecall_index, ecall_name))
        if self.timeout == 0:
            self.explore_and_report(guard.simgr, ecall_addr)
            if debug:
                IPython.embed()
        else:
            try:
                with Timeout(seconds=self.timeout):
                    self.explore_and_report(guard.simgr, ecall_addr)
            except:
                log.error("  Timeout!\n")

    def explore_and_report(self, simgr, ecall_addr):
        simgr.explore()
        log.info("  Exploration finished!")
        log.info("  Simgr: {}".format(simgr))
        reached_ecall = []
        for exit_i in range(len(simgr.exited)):
            for te in simgr.exited[exit_i].enclave.jump_trace:
                if te.address == ecall_addr:
                    reached_ecall.append(simgr.exited[exit_i])
                    break
        for exit_i in range(len(simgr.active)):
            for te in simgr.active[exit_i].enclave.jump_trace:
                if te.address == ecall_addr:
                    reached_ecall.append(simgr.active[exit_i])
                    break
        for exit_i in range(len(simgr.killed)):
            for te in simgr.killed[exit_i].enclave.jump_trace:
                if te.address == ecall_addr:
                    reached_ecall.append(simgr.killed[exit_i])
                    break
        for exit_i in range(len(simgr.violation)):
            for te in simgr.violation[exit_i].enclave.jump_trace:
                if te.address == ecall_addr:
                    reached_ecall.append(simgr.violation[exit_i])
                    break
        log.info("  No. of exited states reaching ecall: {}.\n".format(
            len(reached_ecall)))
