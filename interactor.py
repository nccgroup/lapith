# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

from CmdLineApp import GUIApp
import wx
import sys
from model import NessusReport, NessusItem, NessusTreeItem, MergedNessusReport

from view import ID_Load_Files, ID_Merge_Files

ID_Save_Results = wx.NewId()

def trim(docstring):
    if not docstring:
        return ''
    # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = docstring.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    indent = sys.maxint
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
    # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < sys.maxint:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
    # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    # Return a single string:
    return '\n'.join(trimmed)

class ViewerInteractor(GUIApp.GUIInteractor):
    def bind_events(self):
        # Toolbar events
        self.view.Bind(wx.EVT_TOOL, self.LoadFiles, id=ID_Load_Files)
        self.view.Bind(wx.EVT_TOOL, self.MergeFiles, id=ID_Merge_Files)
        # Tree clicking and selections
        self.view.tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnSelChanged, self.view.tree)
        self.view.tree.Bind(wx.EVT_TREE_ITEM_MENU, self.OnRightClick, self.view.tree)
        # Tab close event - will prevent closing the output tab
        self.view.Bind(wx.aui.EVT_AUINOTEBOOK_PAGE_CLOSE, self.OnPageClose)
        # Menu stuff
        self.view.Bind(wx.EVT_MENU, self.LoadFiles, id=wx.ID_OPEN)
        self.view.Bind(wx.EVT_MENU, self.ExtractResults, id=ID_Save_Results)

    def ExtractResults(self, event):
        item = self.view.tree.GetSelection()
        data = self.view.tree.GetItemData(item).GetData()
        self.controller.tree_menu_click(data)

    def OnRightClick(self, event):
        item = event.GetItem()
        self.view.tree.SelectItem(item)
        data = self.view.tree.GetItemData(item).GetData()
        if isinstance(data, NessusReport) or isinstance(data, MergedNessusReport) or isinstance(data, list):
            menu = wx.Menu()
            menu.Append(ID_Save_Results, "Save all results")
            self.view.PopupMenu(menu)
            menu.Destroy()

    def LoadFiles(self, event):
        self.controller.LoadFiles()

    def MergeFiles(self, event):
        self.controller.combine_files()

    def OnPageClose(self, event):
        idx = event.GetSelection()
        tab = event.GetEventObject().GetPage(idx)
        if tab == self.view.display:
            event.Veto()

    def OnSelChanged(self, event):
        item = event.GetItem()
        tree = self.view.tree
        data = tree.GetItemData(item).GetData()
        if isinstance(data, NessusReport):
            self.view.display.Clear()
            self.view.display.SetValue(data.reportname)
            self.view.notebook.SetSelection(0)
            self.view.tree.SetFocus()
        elif isinstance(data, NessusItem):
            self.view.display.Clear()
            self.view.display.SetValue(data.output.replace('\\n', "\n"))
            self.view.notebook.SetSelection(0)
            self.view.tree.SetFocus()
        elif isinstance(data, NessusTreeItem):
            self.controller.ShowNessusItem(data)
        elif isinstance(data, str):
            self.view.display.Clear()
            self.view.display.SetValue(data.replace('\\n', "\n"))
            self.view.notebook.SetSelection(0)
            self.view.tree.SetFocus()
