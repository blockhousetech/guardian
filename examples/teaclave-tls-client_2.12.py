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
# logging
import logging

angr_logging_level = logging.CRITICAL  # CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET
logging.getLogger('guardian').setLevel(angr_logging_level)
logging.getLogger('angr').setLevel(angr_logging_level)
logging.getLogger('cle.loader').setLevel(angr_logging_level)

## Before fix

# guardian configuration
enclave_path = "examples/teaclave-tls-client_2.12/enclave.signed.so"

# setup angr and guardian projects
proj = angr.Project(enclave_path)
guard = guardian.Project(proj, teaclave=True)
guard.set_target_ecall(0x0)  # set target ecall

# start looking for vulnerabilities
guard.simgr.explore()

# print the list of potential threats
print("Before fix:")
print("Potential violations found: ", guard.simgr.violation)

assert guard.simgr.violation

## After fix

enclave_path = "examples/teaclave-tls-client_2.12/enclave-after-fix.signed.so"

# setup angr and guardian projects
proj = angr.Project(enclave_path)
guard = guardian.Project(proj, teaclave=True)
guard.set_target_ecall(0x0)  # set target ecall

# start looking for vulnerabilities
guard.simgr.explore()

# print the list of potential threats
print("After fix:")
print("Potential violations found: ", guard.simgr.violation)

assert not guard.simgr.violation
