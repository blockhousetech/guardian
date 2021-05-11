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

logging.getLogger("guardian").addHandler(logging.NullHandler())
from .loggers import Loggers

loggers = Loggers()
del Loggers
del logging

from .controlstate import ControlState, Rights, ControlStateName
from .plugins import TraceElement, EnclaveState
from .violation_type import ViolationType
from .hooker import Hooker
from .explorer import EnclaveExploration
from .breakpoints import Breakpoints
from .layout import EnclaveMemoryLayout
from .project import Project

loggers.load_all_loggers()
