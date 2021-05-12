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

from enum import Enum


class ViolationType(Enum):
    OutOfEnclaveRead = 1
    OutOfEnclaveWrite = 2
    OutOfEnclaveJump = 3
    SymbolicRead = 4
    SymbolicWrite = 5
    SymbolicJump = 6
    EntrySanitisation = 7
    ExitSanitisation = 8
    Transition = 9

    def to_string(self):
        if self == ViolationType.OutOfEnclaveRead:
            return "OutOfEnclaveRead"
        elif self == ViolationType.OutOfEnclaveWrite:
            return "OutOfEnclaveWrite"
        elif self == ViolationType.OutOfEnclaveJump:
            return "OutOfEnclaveJump"
        elif self == ViolationType.SymbolicRead:
            return "SymbolicRead"
        elif self == ViolationType.SymbolicWrite:
            return "SymbolicWrite"
        elif self == ViolationType.SymbolicJump:
            return "SymbolicJump"
        elif self == ViolationType.EntrySanitisation:
            return "EntrySanitisation"
        elif self == ViolationType.ExitSanitisation:
            return "ExitSanitisation"
        elif self == ViolationType.Transition:
            return "Transition"
        else:
            assert False

    def to_msg(self):
        return self.to_string() + " violation"
