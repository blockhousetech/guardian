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
import angr, claripy
from .controlstate import ControlState, Rights
from .violation_type import ViolationType
import itertools
import collections

log = logging.getLogger(__name__)


class SimEnclu(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self):
        enclu_length_in_bytes = 3
        if self.state.solver.eval(self.state.regs.eax == 0x0):
            log.debug("EREPORT")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x1):
            log.debug("EGETKEY")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x2):
            log.critical("Unexpected EENTER")
            self.exit(1)
        elif self.state.solver.eval(self.state.regs.eax == 0x4):
            log.critical("Unexpected EEXIT")
            self.exit(1)
        else:
            log.critical("Unexpected ENCLU")
            self.exit(1)


class Nop(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.successors.add_successor(
            self.state, self.state.addr + kwargs["bytes_to_skip"],
            self.state.solver.true, 'Ijk_Boring')


class Empty(angr.SimProcedure):
    def run(self):
        pass


class UD2(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("UD2 detected! Aborting this branch!")
        log.debug(hex(self.state.addr))
        self.successors.add_successor(self.state, self.state.addr,
                                      self.state.solver.true, 'Ijk_NoHook')
        self.exit(2)


class Rdrand(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.state.regs.flags = 1
        self.successors.add_successor(self.state, self.state.addr + 3,
                                      self.state.solver.true, 'Ijk_Boring')


class RegisterEnteringValidation(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### REGISTER ENTERING VALIDATION ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Entering:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         "EnteringSanitisation")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            assert "no_sanitisation" in kwargs
            if not kwargs["no_sanitisation"]:
                violation = Validation.entering(self.state)
                if violation is not None:
                    self.state.enclave.set_violation(violation)
                    self.state.enclave.found_violation = True
        self.state.enclave.entry_sanitisation_complete = True
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToTrusted(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### TRUSTED ###############")
        assert self.state.has_plugin("enclave")
        if not (self.state.enclave.control_state == ControlState.Entering
                or self.state.enclave.control_state == ControlState.Ocall):
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         ControlState.Trusted)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        elif not self.state.enclave.entry_sanitisation_complete:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         "Entering Trusted without entry sanitisation")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.NoReadOrWrite
            self.state.enclave.control_state = ControlState.Trusted
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExiting(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### EXITING ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Trusted:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         ControlState.Exiting)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.Write
            self.state.enclave.control_state = ControlState.Exiting
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExited(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### EXITED ###############")
        assert self.state.has_plugin("enclave")
        if not (self.state.enclave.control_state == ControlState.Exiting
                or self.state.enclave.control_state == ControlState.Entering):
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, ControlState.Exited)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            if self.state.enclave.control_state == ControlState.Exiting:
                assert "no_sanitisation" in kwargs
                if not kwargs["no_sanitisation"]:
                    violation = Validation.exited(self.state)
                    if violation is not None:
                        self.state.enclave.set_violation(violation)
                        self.state.enclave.found_violation = True
            self.state.enclave.control_state = ControlState.Exited
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToOcall(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### OCALL ###############")
        log.debug(hex(self.state.addr))
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Trusted:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, ControlState.Ocall)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.ReadWrite
            self.state.enclave.control_state = ControlState.Ocall
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class OcallAbstraction(angr.SimProcedure):
    def run(self, **kwargs):
        log.debug("######### OCALL ABSTRACTION ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Ocall:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, "OcallAbstraction")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        return self.state.solver.Unconstrained("ocall_ret",
                                               self.state.arch.bits)


class malloc(angr.SimProcedure):
    def run(self, sim_size):
        if self.state.solver.symbolic(sim_size):
            log.warning("Allocating size {}\n".format(sim_size))
            size = self.state.solver.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                log.warning(
                    "Allocation request of %d bytes exceeded maximum of %d bytes; allocating %d bytes",
                    size, self.state.libc.max_variable_size,
                    self.state.libc.max_variable_size)
                size = self.state.libc.max_variable_size
                self.state.add_constraints(sim_size == size)
        else:
            size = self.state.solver.eval(sim_size)
        return self.state.heap._malloc(sim_size)


class Validation:
    def entering(state):
        log.debug("######### VALIDATION REGS ###############")
        state.solver.simplify()
        zeroed_regs = [
            "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        ]
        error_regs = []
        for reg_name in zeroed_regs:
            if state.solver.satisfiable(
                    extra_constraints=[state.registers.load(reg_name) != 0x0]):
                log.debug(
                    "######### ENTERING ZEROED_REG ERROR %s %s ###############",
                    reg_name, state.registers.load(reg_name))
                error_regs.append(reg_name)

        if state.solver.satisfiable(extra_constraints=[state.regs.ac != 0x0]):
            log.debug("######### ENTERING AC ERROR %s ###############",
                      state.regs.ac)
            error_regs.append("ac")
        # DF SET is 0xffffffffffffffff in angr
        # whereas DF CLEAR = 0x1
        if state.solver.satisfiable(
                extra_constraints=[state.regs.dflag != 0x1]):
            log.debug("######### ENTERING DF ERROR %s ###############",
                      state.regs.dflag)
            error_regs.append("df")

        if error_regs:
            return (ViolationType.EntrySanitisation,
                    ViolationType.EntrySanitisation.to_msg(), error_regs)

    def exited(state):
        state.solver.simplify()
        zeroed_regs = [
            "rdx", "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        ]
        error_regs = []
        for reg_name in zeroed_regs:
            if state.solver.satisfiable(
                    extra_constraints=[state.registers.load(reg_name) != 0x0]):
                log.debug(
                    "######### EXITING ZEROED_REG ERROR %s %s ###############",
                    reg_name, state.registers.load(reg_name))
                error_regs.append(reg_name)

        if state.solver.satisfiable(extra_constraints=[state.regs.ac != 0x0]):
            log.debug("######### ENTERING AC ERROR %s ###############",
                      state.regs.ac)
            error_regs.append("ac")
        # DF SET is 0xffffffffffffffff in angr
        # whereas DF CLEAR = 0x1
        if state.solver.satisfiable(
                extra_constraints=[state.regs.dflag != 0x1]):
            log.debug("######### ENTERING DF ERROR %s ###############",
                      state.regs.dflag)
            error_regs.append("df")

        if error_regs:
            return (ViolationType.ExitSanitisation,
                    ViolationType.ExitSanitisation.to_msg(), error_regs)
