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

import os, sys
import logging
import contextlib
import datetime

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

if __name__ == "__main__":
    angr_logging_level = logging.CRITICAL  # CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET
    logging.getLogger('angr').setLevel(angr_logging_level)
    logging.getLogger('cle.loader').setLevel(angr_logging_level)

    # In secs
    timeout = 20 * 60

    enclave_list = [
        ("ae_2.12/qe.so", False, False),
        ("ae_2.12/pce.so", False, False),
        ("ae_2.12/pve.so", False, False),
        ("ae_2.12/le.so", False, False),
        ("teaclave-crypto_2.12/enclave.signed.so", False, True),
        ("teaclave-http-req_2.12/enclave.signed.so", False, True),
        ("teaclave-sealeddata_2.12/enclave.signed.so", False, True),
        ("teaclave-tls-client_2.12/enclave.signed.so", False, True),
        ("contact_discovery_signal_2.1.3/libsabd_enclave.unstripped.so", True,
         False),
        ("sgx-gmp-demo_2.6/EnclaveGmpTest.so", True, False),
        ("wolfssl_2.12/Wolfssl_Enclave.so", False, False),
        ("teerex-tls-client/enclave.signed.so", True, True),
        ("teerex-sgx-gmp/enclave.signed.so", True, False),
        ("teerex-talos/enclave.signed.so", True, False),
        ("teerex-wolfssl/enclave.signed.so", True, False),
    ]

    results_folder = "Results_" + str(datetime.datetime.now(tz=None))

    assert not os.path.exists(results_folder)
    os.makedirs(results_folder)

    for (enclave_path, old_sdk, teaclave) in enclave_list:
        assert timeout >= 0
        print("Checking", enclave_path)
        with open(
                os.path.join(results_folder,
                             'Output_' + enclave_path.replace("/", "_")),
                'w') as f:
            proj = angr.Project(enclave_path)
            guard = guardian.Project(angr_project=proj,
                                     old_sdk=old_sdk,
                                     teaclave=teaclave)
            report = guardian.tools.Report(guardian_project=guard,
                                           timeout=timeout)
            report.save(f)
