import angr
import claripy
# guardian
import guardian 
# pytest
import pytest
# Pathlib for path manipulation
import pathlib

class Project:
    def setup(self,
              path,
              heap_size=None,
              stack_size=None,
              ecalls=None,
              ocalls=None,
              exit_addr=None,
              enter_addr=None,
              target_ecall=0x0,
              violation_check=False):
        self.path = path
        self.proj = angr.Project(self.path)
        self.heap_size = heap_size
        self.stack_size = stack_size
        self.ecalls = ecalls
        self.ocalls = ocalls
        self.exit_addr = exit_addr
        self.enter_addr = enter_addr
        self.guardian_proj = guardian.Project(
            self.proj, self.heap_size, self.stack_size, self.ecalls,
            self.ocalls, self.exit_addr, self.enter_addr, violation_check=violation_check)
        self.guardian_proj.set_target_ecall(target_ecall)
        self.simgr = self.guardian_proj.simgr
        return self.proj, self.simgr


# Before fix
@pytest.fixture
def setup():
    return Project().setup


def test_disable_violation_check(setup):
    """Test that violation detection can be disabled"""
    # guardian configuration
    enclave_path = pathlib.Path(__file__).parent / "disable_violation_check"/ "enclave.signed.so"
    ecalls = [(1, 'sgx_e_mpz_add', 4200800,
            [(4201309, 4201314), (4201351, 4201356),
                (4201459,
                4201464)])]  # can be found manually or by calling heuristics
    find_missing_ecalls_or_ocalls = False  # tell angr not to look for missing ocalls (ecalls we supplied)
    proj, simgr = setup(enclave_path, ecalls=ecalls, target_ecall=0x1, violation_check=False)

    # Test that we can still reach the target ecall (Meaning the setup worked)
    simgr.explore(find=proj.loader.find_symbol('sgx_e_mpz_add').rebased_addr)
    assert simgr.found, "Could not reach target ecall"

    # Test that exploration still works and violation detection is disabled
    simgr.move(from_stash='found', to_stash='active')
    simgr.explore()
    assert not simgr.violation, "Violation found when detection is disabled"

