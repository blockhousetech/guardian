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
from .controlstate import ControlState, ControlStateName
import copy


class EnclaveExploration(angr.exploration_techniques.ExplorationTechnique):

    def __init__(self):
        super().__init__()
        self.stage = ControlState.Entering

    def filter(self, simgr, state, **kwargs):
        return state.enclave.control_state.to_stash_name()

    def setup(self, simgr):
        simgr.stashes[ControlStateName.ExitedStashName] = []
        simgr.stashes[ControlStateName.ViolationStashName] = []
        simgr.stashes[ControlStateName.KilledStashName] = []
        simgr.stashes[ControlStateName.AbortedStashName] = []

    def step_state(self, simgr, state, **kwargs):
        state.enclave.pre_current_state = state.copy()
        simgr_stash_list = simgr.step_state(state, **kwargs)

        if None in simgr_stash_list:
            simgr_stash_list[ControlStateName.KilledStashName] = [
                v for v in simgr_stash_list[None]
                if v.enclave.found_violation and v.enclave.violation is None
            ]
            simgr_stash_list[ControlStateName.ViolationStashName] = [
                v for v in simgr_stash_list[None] if v.enclave.found_violation
                and v.enclave.violation is not None
            ]
            simgr_stash_list[None] = [
                v for v in simgr_stash_list[None]
                if not v.enclave.found_violation
            ]

        return simgr_stash_list

    def complete(self, simgr):
        return len(simgr.stashes["active"]) > 99 or len(
            simgr.stashes[ControlStateName.ViolationStashName]) > 19
