# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

import os
from setuptools import setup
from py2exe.build_exe import py2exe

#--------------------------------------------------------------------------
#
# Define our own command class based on py2exe so we can perform some
# customizations, and in particular support UPXing the binary files.
#
#--------------------------------------------------------------------------

class Py2exe(py2exe):

    def initialize_options(self):
        # Add a new "upx" option for compression with upx
        py2exe.initialize_options(self)
        self.upx = 1

    def copy_file(self, *args, **kwargs):
        # Override to UPX copied binaries.
        (fname, copied) = result = py2exe.copy_file(self, *args, **kwargs)

        basename = os.path.basename(fname)
        if (copied and self.upx and
            (basename[:6]+basename[-4:]).lower() != 'python.dll' and
            fname[-4:].lower() in ('.pyd', '.dll')):
            os.system('upx --best "%s"' % os.path.normpath(fname))
        return result

    def patch_python_dll_winver(self, dll_name, new_winver=None):
        # Override this to first check if the file is upx'd and skip if so
        if not self.dry_run:
            if not os.system('upx -qt "%s" >nul' % dll_name):
                if self.verbose:
                    print "Skipping setting sys.winver for '%s' (UPX'd)" % \
                          dll_name
            else:
                py2exe.patch_python_dll_winver(self, dll_name, new_winver)
                # We UPX this one file here rather than in copy_file so
                # the version adjustment can be successful
                if self.upx:
                    os.system('upx --best "%s"' % os.path.normpath(dll_name))


version="0.1.0"

py2exe_options = dict(
                    compressed=True,
                    optimize=2,
                    bundle_files=1,
                    excludes=[
                       "_ssl",
                       "doctest",
                       "pdb",
                       "unittest",
                       "inspect",
                       ],
                   )
setup(
        name="NessusViewer",
#        cmdclass= {'py2exe': Py2exe},
        version=version,
        test_suite="nose.collector",
        test_requires=["Nose"],
        description="Slice .nessus files the useful way",
        windows=["viewer.py"],
        scripts=["viewer.py"],
        packages=["model", "view", "controller"],
        options={"py2exe": py2exe_options},
#        install_requires=["wx"],
        zipfile=None,
    )
