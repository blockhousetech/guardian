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

import logging, sys
import angr
import sys
import pyvex
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from .simulation_procedures import malloc, Empty, TransitionToTrusted, TransitionToExiting, TransitionToOcall, TransitionToTrusted, OcallAbstraction, TransitionToExited, RegisterEnteringValidation, SimEnclu, Nop, Rdrand, UD2
from .controlstate import ControlState

log = logging.getLogger(__name__)


class Hooker:

    def __init__(self, violation_check=True):
        """Setup with or without violation check."""
        self.violation_check = violation_check

    def setup(self, proj, simgr, ecalls, ocalls, exited_addr, enter_addr,
              old_sdk):
        self.instruction_hooker(proj,
                                self.instruction_replacement(exited_addr))
        self.libc_functions_hooker(proj)
        self.transitions_hooker(proj, ecalls, ocalls, exited_addr, enter_addr,
                                old_sdk)
        return proj, simgr

    def instruction_hooker(self, angr_proj, ins_to_sim_proc):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.skipdata = True
        for section in angr_proj.loader.main_object.sections:
            if section.is_executable:
                section_bytes = angr_proj.loader.memory.load(
                    section.vaddr, section.memsize)
                for i in md.disasm(section_bytes, section.vaddr):
                    sim_proc = ins_to_sim_proc(i)
                    if sim_proc != None:
                        logging.debug(
                            "0x%x:\t%s\t%s\t%s" %
                            (i.address, i.mnemonic, i.op_str, i.size))
                        angr_proj.hook(i.address, hook=sim_proc, length=i.size)

    def libc_functions_hooker(self, proj):
        proj.hook_symbol("dlmalloc", malloc())
        proj.hook_symbol("dlfree", angr.SIM_PROCEDURES['libc']['free']())
        proj.hook_symbol("printf", Empty())
        proj.hook_symbol("memcpy", angr.SIM_PROCEDURES['libc']['memcpy']())
        proj.hook_symbol("memset", angr.SIM_PROCEDURES['libc']['memset']())
        proj.hook_symbol("dlrealloc", angr.SIM_PROCEDURES['libc']['realloc']())

    def transitions_hooker(self, proj, ecalls, ocalls, exit_addr, enter_addr,
                           old_sdk):
        if ecalls is not None:
            for (ecall_index, ecall_name, ecall_addr, ecall_rets) in ecalls:
                for (call_addr, ret_addr) in ecall_rets:
                    proj.hook(call_addr,
                              hook=TransitionToTrusted(
                                  violation_check=self.violation_check))
                    proj.hook(ret_addr,
                              hook=TransitionToExiting(
                                  violation_check=self.violation_check))
        if ocalls is not None:
            for (ocall_name, ocall_addr, sgx_ocalls, ocall_rets) in ocalls:
                proj.hook(ocall_addr,
                          hook=TransitionToOcall(
                              violation_check=self.violation_check))
                for ret_addr in ocall_rets:
                    proj.hook(ret_addr,
                              hook=TransitionToTrusted(
                                  violation_check=self.violation_check))

        sgx_ocall_addr = proj.loader.find_symbol("sgx_ocall").rebased_addr
        proj.hook(sgx_ocall_addr, hook=OcallAbstraction())
        proj.hook(exit_addr,
                  hook=TransitionToExited(
                      no_sanitisation=old_sdk,
                      violation_check=self.violation_check))
        proj.hook(enter_addr,
                  hook=RegisterEnteringValidation(
                      no_sanitisation=old_sdk,
                      violation_check=self.violation_check))

    def instruction_replacement(self, exit_addr):

        def replace(capstone_instruction) -> angr.SimProcedure:
            if capstone_instruction.mnemonic == "enclu" and capstone_instruction.address != exit_addr:
                return SimEnclu(violation_check=True)
            elif capstone_instruction.mnemonic == "xsave64":
                return Nop(bytes_to_skip=4)
            elif capstone_instruction.mnemonic == "xrstor64":
                return Nop(bytes_to_skip=4)
            elif capstone_instruction.mnemonic == "fxrstor64":
                return Nop(bytes_to_skip=4)
            elif capstone_instruction.mnemonic == "rdrand":
                return Rdrand()
            elif capstone_instruction.mnemonic == "ud2":
                return UD2()
            else:
                None

        return replace
