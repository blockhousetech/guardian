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

# angr
import angr
import claripy
# guardian
import guardian
# pytest
import pytest
#other
from collections import Counter


class Project:

    def setup(self,
              path,
              heap_size=None,
              stack_size=None,
              ecalls=None,
              ocalls=None,
              exit_addr=None,
              enter_addr=None):
        self.path = path
        self.proj = angr.Project(self.path)
        self.heap_size = heap_size
        self.stack_size = stack_size
        self.ecalls = ecalls
        self.ocalls = ocalls
        self.exit_addr = exit_addr
        self.enter_addr = enter_addr
        self.guardian_proj = guardian.Project(self.proj, self.heap_size,
                                              self.stack_size, self.ecalls,
                                              self.ocalls, self.exit_addr,
                                              self.enter_addr)
        self.guardian_proj.set_target_ecall(0x0)
        self.simgr = self.guardian_proj.simgr
        return self.proj, self.simgr


@pytest.fixture
def setup():
    return Project().setup


def test_all_violations(setup):
    proj, simgr = setup("tests/all_violations/enclave.so")
    simgr.explore()

    assert Counter([simgr.violation[i].enclave.violation[0] for i in range(0, len(simgr.violation))]) \
        == Counter([guardian.ViolationType.SymbolicRead, guardian.ViolationType.SymbolicWrite, guardian.ViolationType.SymbolicJump,
                    guardian.ViolationType.OutOfEnclaveRead, guardian.ViolationType.OutOfEnclaveWrite, guardian.ViolationType.OutOfEnclaveJump])


def test_entry_sanitisation(setup):
    proj, simgr = setup("tests/entry_sanitisation/enclave.so")
    proj.hook(0x40685e,
              hook=guardian.simulation_procedures.Nop(bytes_to_skip=31))
    proj.hook(0x4068ac,
              hook=guardian.simulation_procedures.Nop(bytes_to_skip=18))
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.EntrySanitisation

    assert simgr.violation[0].enclave.violation[2] == [
        'rcx', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'ac', 'df'
    ]


def test_exit_sanitisation(setup):
    proj, simgr = setup("tests/exit_sanitisation/enclave.so")
    proj.hook(0x406924,
              hook=guardian.simulation_procedures.Nop(bytes_to_skip=34))
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.ExitSanitisation


def test_good_case(setup):
    proj, simgr = setup("tests/good_case/enclave.so")
    simgr.explore()

    assert len(simgr.violation) == 0


def test_out_of_jump(setup):
    proj, simgr = setup("tests/out_of_jump/enclave.so")
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.OutOfEnclaveJump


def test_out_of_read(setup):
    proj, simgr = setup("tests/out_of_read/enclave.so")
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.OutOfEnclaveRead


def test_out_of_write(setup):
    proj, simgr = setup("tests/out_of_write/enclave.so")
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.OutOfEnclaveWrite


def test_symbolic_jump(setup):
    proj, simgr = setup("tests/symbolic_jump/enclave.so")
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.SymbolicJump


def test_symbolic_jump(setup):
    proj, simgr = setup("tests/symbolic_read/enclave.so")
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.SymbolicRead


def test_symbolic_write(setup):
    proj, simgr = setup("tests/symbolic_write/enclave.so")
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.SymbolicWrite


def test_transition(setup):
    proj = angr.Project("tests/transition/enclave.so")
    ecalls = [(ind, name, add, [(io[0][0], 0)])
              for (ind, name, add,
                   io) in guardian.tools.Heuristic.find_ecalls(proj)]
    proj, simgr = setup("tests/transition/enclave.so", ecalls=ecalls)
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.Transition


def test_transition_two(setup):
    proj, simgr = setup("tests/transition2/enclave.so", enter_addr=0x0)
    simgr.explore()

    assert simgr.violation[0].enclave.violation[
        0] == guardian.ViolationType.Transition
