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
"""logger configuration imported from angr repo and modified to include guardian logger"""
import logging
import zlib


class Loggers:

    def __init__(self, default_level=logging.WARNING):
        self.default_level = default_level
        self._loggers = {}
        self.load_all_loggers()

        self.handler = CuteHandler()
        self.handler.setFormatter(
            logging.Formatter(
                '%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))

        if len(logging.root.handlers) == 0:
            self.enable_root_logger()
            logging.root.setLevel(self.default_level)

    IN_SCOPE = ('angr', 'claripy', 'cle', 'pyvex', 'archinfo', 'tracer',
                'driller', 'rex', 'patcherex', 'identifier', 'guardian')

    def load_all_loggers(self):
        """
        A dumb and simple way to conveniently aggregate all loggers.

        Adds attributes to this instance of each registered logger, replacing '.' with '_'
        """
        for name, logger in logging.Logger.manager.loggerDict.items():
            if any(
                    name.startswith(x + '.') or name == x
                    for x in self.IN_SCOPE):
                self._loggers[name] = logger

    def __getattr__(self, k):
        real_k = k.replace('_', '.')
        if real_k in self._loggers:
            return self._loggers[real_k]
        else:
            raise AttributeError(k)

    def __dir__(self):
        return super(Loggers, self).__dir__() + self._loggers.keys()

    def enable_root_logger(self):
        """
        Enable angr's default logger
        """
        logging.root.addHandler(self.handler)

    def disable_root_logger(self):
        """
        Disable angr's default logger
        """
        logging.root.removeHandler(self.handler)

    @staticmethod
    def setall(level):
        for name in logging.Logger.manager.loggerDict.keys():
            logging.getLogger(name).setLevel(level)


class CuteHandler(logging.StreamHandler):

    def emit(self, record):
        color = zlib.adler32(record.name.encode()) % 7 + 31
        try:
            record.name = ("\x1b[%dm" % color) + record.name + "\x1b[0m"
        except Exception:
            pass

        try:
            record.msg = ("\x1b[%dm" % color) + record.msg + "\x1b[0m"
        except Exception:
            pass

        super(CuteHandler, self).emit(record)
