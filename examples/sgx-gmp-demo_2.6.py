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

# Before fix

# guardian configuration
enclave_path = "examples/sgx-gmp-demo_2.6/enclave.signed.so"
ecalls = [
    (1, 'sgx_e_mpz_add', 4200800, [(4201309, 4201314), (4201351, 4201356),
                                   (4201459, 4201464)])
]  # can be found manually or by calling heuristics
find_missing_ecalls_or_ocalls = False  # tell angr not to look for missing ocalls (ecalls we supplied)

# setup angr and guardian projects
proj = angr.Project(enclave_path)
guard = guardian.Project(
    proj,
    ecalls=ecalls,
    find_missing_ecalls_or_ocalls=find_missing_ecalls_or_ocalls)
guard.set_target_ecall(0x1)  # set target ecall

# start looking for vulnerabilities
guard.simgr.explore()

# print the list of potential threats
print("Before fix:")
print("Potential violations found: ", guard.simgr.violation)

assert guard.simgr.violation

# After fix

# guardian configuration
enclave_path = "examples/sgx-gmp-demo_2.6/enclave-after-fix.signed.so"
ecalls = [
    (1, 'sgx_e_mpz_add', 4200800, [(4201309, 4201314), (4201351, 4201356),
                                   (4201459, 4201464)])
]  # can be find manually or by calling heuristics
find_missing_ecalls_or_ocalls = False  # tell angr not to look for missing ocalls (ecalls we supplied)

# setup angr and guardian projects
proj = angr.Project(enclave_path)
guard = guardian.Project(
    proj,
    ecalls=ecalls,
    find_missing_ecalls_or_ocalls=find_missing_ecalls_or_ocalls)
guard.set_target_ecall(0x1)  # set target ecall

# start looking for vulnerabilities
guard.simgr.explore()

# print the list of potential threats
print("After fix:")
print("Potential violations found: ", guard.simgr.violation)

assert not guard.simgr.violation
