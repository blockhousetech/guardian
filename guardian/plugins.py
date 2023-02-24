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
from .controlstate import ControlState, Rights
from copy import deepcopy

log = logging.getLogger(__name__)


class TraceElement:

    def __init__(self, project, addr):
        self.address = addr
        self.symbol = None
        symbol = project.loader.find_symbol(self.address)
        if symbol is not None:
            self.symbol = symbol.name


class EnclaveState(angr.SimStatePlugin):

    def __init__(self,
                 proj=None,
                 control_state=ControlState.Entering,
                 ooe_rights=Rights.ReadWrite,
                 violation=None,
                 found_violation=False,
                 jump_trace=None,
                 call_stack=None,
                 entry_sanitisation_complete=False):
        super().__init__()
        self.found_violation = found_violation
        self.violation = violation
        self.control_state = control_state
        self.ooe_rights = ooe_rights
        self.jump_trace = jump_trace
        self.call_stack = call_stack
        self.entry_sanitisation_complete = entry_sanitisation_complete

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return EnclaveState(
            control_state=self.control_state,
            ooe_rights=self.ooe_rights,
            found_violation=self.found_violation,
            violation=deepcopy(self.violation)
            if self.violation is not None else None,
            jump_trace=self.jump_trace.copy(),
            call_stack=self.call_stack.copy(),
            entry_sanitisation_complete=self.entry_sanitisation_complete)

    def init_trace_and_stack(self):
        self.jump_trace = [TraceElement(self.state.project, self.state.addr)]
        self.call_stack = [TraceElement(self.state.project, self.state.addr)]

    def print_trace(self, only_elements_with_symbol=True):
        print("Trace:\n")
        for te in self.jump_trace:
            if not only_elements_with_symbol or te.symbol is not None:
                print("{} @ {} \n".format(hex(te.address), te.symbol))
        print("\n")

    def print_call_stack(self, only_elements_with_symbol=True):
        print("Callstack:\n")
        for te in self.call_stack:
            # if not only_elements_with_symbol or te.symbol is not None:
            print("{} @ {} \n".format(hex(te.address), te.symbol))
        print("\n")

    def set_violation(self, violation):
        self.violation = violation
        log.warning("   Violation @ {} : {}".format(hex(self.state.addr),
                                                    self.violation))
