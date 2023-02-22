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
import guardian
import pytest
import pathlib

FILE_DIR = pathlib.Path(__file__).parent

class Project:
    """A class to setup a project and simulation manager for testing."""

    def setup(
        self,
        path,
        heap_size=None,
        stack_size=None,
        ecalls=None,
        ocalls=None,
        exit_addr=None,
        enter_addr=None,
    ):
        self.path = path
        self.proj = angr.Project(self.path)
        self.heap_size = heap_size
        self.stack_size = stack_size
        self.ecalls = ecalls
        self.ocalls = ocalls
        self.exit_addr = exit_addr
        self.enter_addr = enter_addr
        self.guardian_proj = guardian.Project(
            self.proj,
            self.heap_size,
            self.stack_size,
            self.ecalls,
            self.ocalls,
            self.exit_addr,
            self.enter_addr,
            violation_check=False, # Disable violation check
        )
        
        self.guardian_proj.set_target_ecall(0x0)
        self.simgr = self.guardian_proj.simgr
        return self.proj, self.simgr


@pytest.fixture
def setup():
    return Project().setup


def test_all_violations(setup):
    proj, simgr = setup(FILE_DIR/"all_violations"/"enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_entry_sanitisation(setup):
    proj, simgr = setup(FILE_DIR /"entry_sanitisation"/"enclave.so")
    proj.hook(0x40685E, hook=guardian.simulation_procedures.Nop(bytes_to_skip=31))
    proj.hook(0x4068AC, hook=guardian.simulation_procedures.Nop(bytes_to_skip=18))
    simgr.explore()

    assert len(simgr.violation) == 0


def test_exit_sanitisation(setup):
    proj, simgr = setup(FILE_DIR/"exit_sanitisation"/"enclave.so")
    proj.hook(0x406924, hook=guardian.simulation_procedures.Nop(bytes_to_skip=34))
    simgr.explore()

    assert len(simgr.violation) == 0


def test_good_case(setup):
    proj, simgr = setup(FILE_DIR/"good_case"/"enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_out_of_jump(setup):
    proj, simgr = setup(FILE_DIR/"out_of_jump"/"enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_out_of_read(setup):
    proj, simgr = setup(FILE_DIR/"out_of_read"/"enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_out_of_write(setup):
    proj, simgr = setup(FILE_DIR/"out_of_write"/"enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_symbolic_jump(setup):
    proj, simgr = setup(FILE_DIR/"symbolic_jump"/"enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_symbolic_write(setup):
    proj, simgr = setup(FILE_DIR/"symbolic_write"/"enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_transition(setup):
    proj = angr.Project(FILE_DIR/"transition"/"enclave.so")
    ecalls = [
        (ind, name, add, [(io[0][0], 0)])
        for (ind, name, add, io) in guardian.tools.Heuristic.find_ecalls(proj)
    ]
    proj, simgr = setup(FILE_DIR/"transition"/"enclave.so", ecalls=ecalls)
    simgr.explore()

    assert len(simgr.violation) == 0


def test_transition_two(setup):
    proj, simgr = setup(FILE_DIR/"transition2"/"enclave.so", enter_addr=0x0)
    simgr.explore()

    assert len(simgr.violation) == 0
