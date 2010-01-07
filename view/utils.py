import wx
import wx.aui
import os

class ModalProgressBar(wx.ProgressDialog):
    def __init__(self, parent, title="", text="", maximum=1):
        wx.ProgressDialog.__init__(self, title,
                text,
                maximum=maximum,
                parent=parent,
                style=wx.PD_APP_MODAL
                )

    def update(self, count, text):
        self.Update(count, text)
            
    def done(self):
        self.Destroy()

class SaveDialog(wx.FileDialog):
    def __init__(self, parent, message="Save file as...", defaultDir=os.getcwd(), defaultFile="", wildcard="All files (*.*)|*.*", style=wx.SAVE):
        wx.FileDialog.__init__(self,
                parent,
                message=message,
                defaultDir=defaultDir,
                defaultFile=defaultFile,
                wildcard=wildcard,
                style=style
                )

    def get_choice(self):
        if self.ShowModal() == wx.ID_OK:
            path = self.GetPath()
            self.Destroy()
            return path
        else:
            self.Destroy()
            return None

class FileDialog(wx.FileDialog):
    def __init__(self, parent, message="", defaultDir=os.getcwd(), defaultFile="", wildcard="All files (*.*)|*.*", multiple=False):
        if multiple:
            style=wx.OPEN | wx.MULTIPLE | wx.CHANGE_DIR
        else:
            style=wx.OPEN | wx.CHANGE_DIR
        wx.FileDialog.__init__(self,
                parent,
                message=message,
                defaultDir=defaultDir,
                defaultFile=defaultFile,
                wildcard=wildcard,
                style=style
                )

    def get_choice(self):
        if self.ShowModal() == wx.ID_OK:
            paths = self.GetPaths()
            self.Destroy()
            return paths
        else:
            self.Destroy()
            return None

class MessageBox(wx.MessageDialog):
    def __init__(self, parent, string, title="Message", style=wx.OK | wx.ICON_INFORMATION):
        wx.MessageDialog(self, parent,
                string,
                title,
                style
                )
