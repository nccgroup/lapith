# Lapith

Lapith is a Python GUI tool that presents Nessus results in a format more useful for penetration testers. Results can be viewed by issue as opposed to by host. It is therefore easier to report all the hosts affected by an issue, rather than all of the issues affecting the host.

Multiple results files can be opened and viewed individually. All open files can then be merged together into a single report, making it easier to report the results of multiple scans.

Results files can be dragged and dropped onto the left-hand tree pane in order to open them. Individual rating levels can be saved out as text files by right clicking on the appropriate item in the treeview.

Various export options are supported: CSV, XML, and restructured text. If the results of a plug-in differ between hosts then a separate tab will appear showing the diff output. Note that host names and IP addresses are excluded from the plug-in output when computing the diffs.

# Requirements

Lapith requires Python 2.7 and the WXPython GUI library. The Jinja2 templating language is also required for the various export options.

WX Python can be downloaded from: http://www.wxpython.org/download.php#stable
Jinja2 can be installed using PIP (pip install jinja2) or from Pypi: https://pypi.python.org/pypi/Jinja2

Lapith is released under the AGPL. Full details of the licence can be found in the LICENSE file.
Source code is available on github: http://github.com/nccgroup/lapith

# Author 

Felix Ingram @lllamaboy

http://stupentest.net/

http://github.com/lllama

http://bitbucket.com/lllama 
