# Guardian

### What is it?

Guardian is a tool that uses symbolic execution to validate
whether an SGX enclave binary is orderly according to the definition in [[1]](#1)—it also tries
to detect typical enclave attack primitives in the process. It uses angr [[2]](#2)—a symbolic
execution engine that focus on usability—as a backend.

### Licence

Guardian is licensed under the GNU Affero General Public License v3.0. If you have any queries about that, please reach out to [us](mailto:research@tbtl.com).

## Running Guardian

### Prerequisites

Guardian requires [Python 3.6 or newer](https://docs.python.org/3/using/index.html) --- make sure you have *pip for Python3* installed. It also relies on [angr](https://github.com/angr/angr) [[2]](#2), which can be installed using pip as follows:

`pip install angr`

### Setup

You can setup Guardian using pip or tox automation tool.

#### pip

Run `pip install .` in the main folder of the Guardian repository.
> :warning: If you get `AttributeError: module 'enum' has no attribute 'IntFlag'` error, check if you have enum34 library installed, which is not compatibile with Python >3.4. You can uninstall it by calling `pip uninstall -y enum34`. This step is not required if you use tox.
> 
> :warning: If you want to run tests, you need pytest framework. You can either install it via pip or use tox, which installs pytest automatically. If you want to use pip, call `pytest` in the main folder of the Guardian repository.

#### tox

Guardian supports tox automation tool. You can install tox using pip by calling `pip install tox`. Once you have tox installed, simply call `tox` in the main folder of the Guardian repository. By default, it will run some tests under Python 3.6, 3.7, and 3.8. You can modify this behaviour by editing the file `tox.ini`.

## Breakdown of the repository structure

Guardian repository comes with the main tool, evaluation script referenced in [[1]](#1), examples, and some tests.

### guardian

It contains the content of the Guardian tool package that you install, either using tox or pip.

### evaluation

This folder contains SGX enclave binaries and a script we used in the vulnerability analysis in [[1]](#1). You should be able to reproduce our evaluation by running, from this folder:

`python evaluation.py`

### examples

In this folder, you can find several scripts: `*.py` and `*-after-fix.py`, together with some SGX enclave binaries. These scripts expose vulnerabilities we found during our analysis in [[1]](#1) and demonstrate these issues have been resolved after reporting them to the maintainers. If you want to run these scripts using tox, you will have to modify `tox.ini`.
> :warning: If you want to run these examples, make sure that your current working directory is the main folder of the Guardian repository.

You can run specific examples by executing, for instance, the following:

`python examples/sgx-gmp-demo_2.6.py`

### tests

Here, you can find a limited number of tests for our tool, together with some SGX enclave binaries they use. The purpose of these tests is to ascertain that violations types are correctly reported and that we do not detect any false-positives. If you set up Guardian using pip, you can run tests by calling `pytest` in the main folder of the Guardian repository. Alternatively, `tox` will run them automatically for you.

## Citing

Guardian is a part of the research effort that we present in [[1]](#1). If you want to refer to our work, please use the following BibTeX entry for citation.

```
@InProceedings{AntoninoWoloszynRoscoe:Guardian:-symbolic-execution-of-orderly-SGX-enclaves,
author = {Pedro Antonino and Wojciech Aleksander Wołoszyn and Andrew William Roscoe},
title = {Guardian: symbolic execution of orderly SGX enclaves},
year = {2021},
note = {Under review},
keywords = {under-review}
}
```

## References
<a id="1">[1]</a> Antonino, Pedro and Wołoszyn, Wojciech Aleksander and Roscoe, Andrew William (2021). 
Guardian: symbolic execution of orderly SGX enclaves. 
Under review.

<a id="2">[2]</a> Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, John and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni (2016).
IEEE Symposium on Security and Privacy.
