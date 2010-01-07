# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

from distutils.core import setup
import py2exe

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
        windows=["viewer.py"],
        options={"py2exe": py2exe_options},
#        zipfile=None,
    )
