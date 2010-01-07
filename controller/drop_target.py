# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

import wx

class MyFileDropTarget(wx.FileDropTarget):
    def __init__(self, window, handlers, error):
        wx.FileDropTarget.__init__(self)
        self.window = window
        self.handlers = handlers
        self.error = error

    def OnDropFiles(self, x, y, filenames):
        did_hosts = False
        for file_ in filenames:
            ext = file_.split(".")[-1]
            if ext in self.handlers:
                self.handlers[ext](file_)
            else:
                self.error(file_)
