# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2017 Ruffin White <roxfoxpox@gmail.com>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------
from __future__ import with_statement
import os
import re
from apparmor.common import AppArmorException, open_file_read, warn, convert_regexp  # , msg, error, debug
from apparmor.regex import re_match_include

from apparmor.severity import Severity as AASeverity

class Severity(AASeverity):
    def __init__(self, dbname=None, default_rank=10):
        """Initialises the class object"""
        self.PROF_DIR = '/etc/comarmor.d'  # The profile directory
        self.NOT_IMPLEMENTED = '_-*not*implemented*-_'  # used for rule types that don't have severity ratings
        self.severity = dict()
        self.severity['DATABASENAME'] = dbname
        self.severity['CAPABILITIES'] = {}
        self.severity['FILES'] = {}
        self.severity['REGEXPS'] = {}
        self.severity['DEFAULT_RANK'] = default_rank
        # For variable expansions for the profile
        self.severity['VARIABLES'] = dict()
        if not dbname:
            raise AppArmorException("No severity db file given")

        with open_file_read(dbname) as database:  # open(dbname, 'r')
            for lineno, line in enumerate(database, start=1):
                line = line.strip()  # or only rstrip and lstrip?
                if line == '' or line.startswith('#'):
                    continue
                if line.startswith('/'):
                    try:
                        path, perms_dict = self.set_perms_dict(line)
                    except ValueError:
                        raise AppArmorException("Insufficient values for permissions in file: %s\n\t[Line %s]: %s" % (dbname, lineno, line))
                    else:
                        for perm_key, perm_value in perms_dict.items():
                            if perm_value not in range(0, 11):
                                raise AppArmorException("Inappropriate values for permissions in file: %s\n\t[Line %s]: %s" % (dbname, lineno, line))
                        path = path.lstrip('/')
                        if '*' not in path:
                            self.severity['FILES'][path] = perms_dict
                        else:
                            ptr = self.severity['REGEXPS']
                            pieces = path.split('/')
                            for index, piece in enumerate(pieces):
                                if '*' in piece:
                                    path = '/'.join(pieces[index:])
                                    regexp = convert_regexp(path)
                                    ptr[regexp] = {'AA_RANK': perms_dict}
                                    break
                                else:
                                    ptr[piece] = ptr.get(piece, {})
                                    ptr = ptr[piece]
                elif line.startswith('CAP_'):
                    try:
                        resource, severity = line.split()
                        severity = int(severity)
                    except ValueError:
                        error_message = 'No severity value present in file: %s\n\t[Line %s]: %s' % (dbname, lineno, line)
                        #error(error_message)
                        raise AppArmorException(error_message)  # from None
                    else:
                        if severity not in range(0, 11):
                            raise AppArmorException("Inappropriate severity value present in file: %s\n\t[Line %s]: %s" % (dbname, lineno, line))
                        self.severity['CAPABILITIES'][resource] = severity
                else:
                    raise AppArmorException("Unexpected line in file: %s\n\t[Line %s]: %s" % (dbname, lineno, line))

    # @abstractmethod  FIXME - uncomment when python3 only
    def set_perms_dict(self, line):
        '''compare if rule-specific variables are equal'''
        raise NotImplementedError("'%s' needs to implement is_equal_localvars(), but didn't" % (str(self)))


class TopicSeverity(Severity):
    def set_perms_dict(self, line):
        '''compare if rule-specific variables are equal'''

        path, subscribe, publish, relay = line.split()
        perms_dict = {
            's': int(subscribe),
            'p': int(publish),
            'r': int(relay)
        }
        return path, perms_dict
