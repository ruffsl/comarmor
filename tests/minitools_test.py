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
import os
import shutil
import subprocess
import sys
import unittest
from common import CATest, setup_all_loops, setup_ca

import comarmor.tools

from comarmor import ca
from common import read_file

from argparse import Namespace

python_interpreter = 'python'
if sys.version_info >= (3, 0):
    python_interpreter = 'python3'

PWD = os.path.dirname(os.path.realpath(__file__))
test_profiles_dir = os.path.join(PWD, 'comarmor.d')

class MinitoolsTest(CATest):

    def CASetup(self):
        self.createTmpdir()

        #copy the local profiles to the test directory
        #Should be the set of cleanprofile
        self.profile_dir = '%s/profiles' % self.tmpdir
        shutil.copytree(test_profiles_dir, self.profile_dir, symlinks=True)

        ca.profile_dir = self.profile_dir

        # # Path for the program
        # self.test_path = '/usr/sbin/winbindd'
        # # Path for the target file containing profile
        # self.local_profilename = '%s/usr.sbin.winbindd' % self.profile_dir

    def test_cleanprof(self):
        input_file = os.path.join(PWD,'data','cleanprof_test.in')
        output_file = os.path.join(PWD,'data','cleanprof_test.out')
        #We position the local testfile
        shutil.copy(input_file, self.profile_dir)
        #Our silly test program whose profile we wish to clean
        cleanprof_test = '/simple/cleanprof/test/profile'

        args = Namespace(dir=self.profile_dir, program=cleanprof_test, silent=True, do_reload=False)
        clean = comarmor.tools.ca_tools('cleanprof', args)

        clean.cleanprof_act(self.profile_dir)

        # subprocess.check_output('%s ./../bin/ca-cleanprof  -d %s -s %s' % (python_interpreter, self.profile_dir, cleanprof_test), shell=True)

        #Strip off the first line (#modified line)
        subprocess.check_output('sed -i 1d %s/%s' % (self.profile_dir, input_file), shell=True)

        exp_content = read_file('./%s' % output_file)
        real_content = read_file('%s/%s' % (self.profile_dir, input_file))
        self.maxDiff = None
        self.assertEqual(exp_content, real_content, 'Failed to cleanup profile properly')


setup_ca(ca)
setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=2)
