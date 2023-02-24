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

import logging
import angr
import claripy
from .plugins import TraceElement
from .controlstate import ControlState, Rights, ControlStateName
from .violation_type import ViolationType
import copy

log = logging.getLogger(__name__)


class Breakpoints:

    def setup(self, proj, simgr, layout, violation_check=True):

        # Violation detection breakpoints
        if violation_check:
            simgr.active[0].inspect.b(
                'mem_read',
                when=angr.BP_BEFORE,
                action=lambda s: self.detect_read_violations(simgr, s, layout))
            simgr.active[0].inspect.b(
                'mem_write',
                when=angr.BP_BEFORE,
                action=lambda s: self.detect_write_violations(
                    simgr, s, layout))
            simgr.active[0].inspect.b(
                'exit',
                when=angr.BP_BEFORE,
                action=lambda s: self.detect_jump_violations(simgr, s, layout))

        # Call stack tracking breakpoints
        simgr.active[0].inspect.b(
            'call',
            when=angr.BP_BEFORE,
            action=lambda st: st.enclave.call_stack.append(
                TraceElement(st.project,
                             st.solver.eval(st.inspect.function_address))))
        simgr.active[0].inspect.b('return',
                                  when=angr.BP_BEFORE,
                                  action=self.delete_last_call_if_exists)

        # Trace tracking breakpoint
        simgr.active[0].inspect.b(
            'exit',
            when=angr.BP_AFTER,
            action=lambda st: st.enclave.jump_trace.append(
                TraceElement(st.project, st.solver.eval(st.inspect.exit_target)
                             )))

        # Memory tracking
        simgr.active[0].inspect.b(
            'mem_read',
            when=angr.BP_AFTER,
            action=lambda s: self.outside_memory_read_detection(s, layout))
        return proj, simgr

    def outside_memory_read_detection(self, state, layout):
        addr = state.inspect.mem_read_address
        assert state.inspect.mem_read_length is not None
        length = state.inspect.mem_read_length
        allowed_range_begin = layout.base_addr
        allowed_range_end = allowed_range_begin + layout.enclave_size - length

        if state.solver.satisfiable(extra_constraints=[
                claripy.Or(addr < allowed_range_begin,
                           addr > allowed_range_end)
        ]):
            state.inspect.mem_read_expr = state.solver.Unconstrained(
                "symb_read", length * 8)

    def delete_last_call_if_exists(self, state):
        if state.enclave.call_stack is not None and state.enclave.call_stack:
            del state.enclave.call_stack[-1]

    def detect_read_violations(self, simgr, state, layout):
        read_allowed = (state.enclave.ooe_rights
                        == Rights.ReadWrite) or (state.enclave.ooe_rights
                                                 == Rights.Read)
        addr = state.inspect.mem_read_address
        assert state.inspect.mem_read_length is not None
        length = state.inspect.mem_read_length
        allowed_range_begin = layout.base_addr
        allowed_range_end = allowed_range_begin + layout.enclave_size - length
        violation = None

        if state.solver.satisfiable(extra_constraints=[
                claripy.Or(addr < allowed_range_begin,
                           addr > allowed_range_end)
        ]):
            if not read_allowed:
                log.warning(
                    "\nState @{} \n!!!!!!! VIOLATION: OUT-OF-ENCLAVE READ !!!!!!!!\n  Address {}\n  constraints were {}\n"
                    .format(hex(state.addr), addr, state.solver.constraints))
                violation = (ViolationType.OutOfEnclaveRead,
                             ViolationType.OutOfEnclaveRead.to_msg(),
                             state.inspect.mem_read_address,
                             state.inspect.mem_read_expr)
            else:
                state.solver.add(
                    claripy.Or(addr < allowed_range_begin,
                               addr > allowed_range_end))

        elif not read_allowed and state.solver.symbolic(
                addr) and not state.solver.single_valued(addr):
            log.warning(
                "\nState @{} \n!!!!!!! VIOLATION: SYMBOLIC READ ADDRESS !!!!!!!!\n  Address {}\n  Value {}\n  constraints were {}\n"
                .format(hex(state.addr), addr, state.inspect.mem_read_expr,
                        state.solver.constraints))
            violation = (ViolationType.SymbolicRead,
                         ViolationType.SymbolicRead.to_msg(),
                         state.inspect.mem_read_address,
                         state.inspect.mem_read_expr)

        if violation is not None:
            state.enclave.found_violation = True
            state_copy = state.copy()
            state_copy.enclave.set_violation(violation)
            self.append_violation_state(simgr, state_copy)

    def detect_write_violations(self, simgr, state, layout):
        write_allowed = state.enclave.ooe_rights == Rights.ReadWrite or state.enclave.ooe_rights == Rights.Write
        addr = state.inspect.mem_write_address
        length = state.solver.eval(state.inspect.mem_write_length) if state.inspect.mem_write_length is not None \
                else len(state.inspect.mem_write_expr) // state.arch.byte_width
        allowed_range_begin = layout.base_addr
        allowed_range_end = allowed_range_begin + layout.enclave_size - length
        violation = None

        if not write_allowed and state.solver.satisfiable(extra_constraints=[
                claripy.Or(addr < allowed_range_begin,
                           addr > allowed_range_end)
        ]):
            log.warning(
                "\nState @{} \n!!!!!!! VIOLATION: OUT-OF-ENCLAVE WRITE !!!!!!!!\n  Address {}\n  Value {}\n  constraints were {}\n"
                .format(hex(state.addr), addr, state.inspect.mem_write_expr,
                        state.solver.constraints))
            violation = (ViolationType.OutOfEnclaveWrite,
                         ViolationType.OutOfEnclaveWrite.to_msg(),
                         state.inspect.mem_write_address,
                         state.inspect.mem_write_expr)

        elif not write_allowed and state.solver.symbolic(
                addr) and not state.solver.single_valued(addr):
            log.warning(
                "\nState @{} \n!!!!!!! VIOLATION: SYMBOLIC WRITE ADDRESS !!!!!!!!\n  Address {}\n  Value {}\n  constraints were {}\n"
                .format(hex(state.addr), addr, state.inspect.mem_write_expr,
                        state.solver.constraints))
            violation = (ViolationType.SymbolicWrite,
                         ViolationType.SymbolicWrite.to_msg(),
                         state.inspect.mem_write_address,
                         state.inspect.mem_write_expr)

        if violation is not None:
            state.enclave.found_violation = True
            state_copy = state.copy()
            state_copy.enclave.set_violation(violation)
            self.append_violation_state(simgr, state_copy)

    def detect_jump_violations(self, simgr, state, layout):
        target = state.inspect.exit_target
        if isinstance(target, angr.state_plugins.SimActionObject):
            target = target.to_claripy()
        allowed_range_begin = layout.base_addr
        allowed_range_end = allowed_range_begin + layout.enclave_size - 1
        violation = None

        if state.solver.satisfiable(extra_constraints=[
                claripy.Or(target < allowed_range_begin,
                           target > allowed_range_end)
        ]):
            log.warning(
                "\nState @{} \n!!!!!!! VIOLATION: OUT-OF-ENCLAVE JUMP !!!!!!!!\n  Target {}\n  constraints were {}\n"
                .format(hex(state.addr), target, state.solver.constraints))
            violation = (ViolationType.OutOfEnclaveJump,
                         ViolationType.OutOfEnclaveJump.to_msg(), target)
        elif state.solver.symbolic(
                target) and not state.solver.single_valued(target):
            log.warning(
                "\nState @{} \n!!!!!!! VIOLATION: SYMBOLIC JUMP TARGET !!!!!!!!\n  Target {}\n  constraints were {}\n"
                .format(hex(state.addr), target, state.solver.constraints))
            violation = (ViolationType.SymbolicJump,
                         ViolationType.SymbolicJump.to_msg(), target)

        if violation is not None:
            state.enclave.found_violation = True
            state_copy = state.copy()
            state_copy.enclave.set_violation(violation)
            self.append_violation_state(simgr, state_copy)

    def append_violation_state(self, simgr, state):
        simgr.stashes[ControlStateName.ViolationStashName].append(state)
