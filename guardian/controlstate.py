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


class ControlStateName:
    ExitedStashName = "exited"
    ViolationStashName = "violation"
    AbortedStashName = "aborted"
    KilledStashName = "killed"


class ControlState(Enum):
    Entering = 1
    Trusted = 2
    Exiting = 3
    Exited = 4
    Aborted = 5
    Ocall = 6

    def to_stash_name(self):
        if self == ControlState.Entering or self == ControlState.Trusted or self == ControlState.Exiting:
            return "active"
        elif self == ControlState.Exited:
            return ControlStateName.ExitedStashName
        elif self == ControlState.Aborted:
            return ControlStateName.AbortedStashName


class Rights(Enum):
    NoReadOrWrite = 1
    Read = 2
    Write = 3
    ReadWrite = 4
