# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

import wx
import wx.aui

ID_About = wx.NewId()
ID_Load_Files = wx.NewId()
ID_Merge_Files = wx.NewId()
ID_Generate_CSV = wx.NewId()
ID_Generate_VulnXML = wx.NewId()
ID_Search = wx.NewId()
ID_Generate_RST = wx.NewId()

class ViewerView(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None)

        self.set_icon()
        self._mgr = wx.aui.AuiManager()
        self._mgr.SetManagedWindow(self)

        self.add_menubar()
        self.statusbar = self.CreateStatusBar(2, wx.ST_SIZEGRIP)
        self.set_statusbar()
        self.set_size()
        self.add_toolbars()
        self.add_panes()
        self.format_panes()
        self._mgr.Update()

    def set_icon(self):
#        iconFile = "search.ico"
#        icon1 = wx.Icon(iconFile, wx.BITMAP_TYPE_ICO)
#        self.SetIcon(icon1)
        self.SetTitle("Nessus Viewer")

    def add_panes(self):
        self.add_tree_pane()
        self.add_display_pane()

    def format_panes(self):
        self._mgr.GetPane("host_tree").Show().Left().Layer(0).Row(0).Position(0)

    def add_tree_pane(self):
        panel = wx.Panel(self, -1)
        sizer = wx.BoxSizer(wx.VERTICAL)
        tree = wx.TreeCtrl(panel, -1, wx.Point(0, 0), wx.Size(200, 250),
                           wx.TR_DEFAULT_STYLE | wx.NO_BORDER)
        label = wx.StaticText(panel, -1, "Filter results")
        self.search = wx.SearchCtrl(panel,  style=wx.TE_PROCESS_ENTER)
        sizer.Add(tree, 1, wx.EXPAND, 0)
        sizer.Add((15,5))
        sizer.Add(label, 0, wx.ALL, 2)
        sizer.Add(self.search, 0, wx.EXPAND, 5)
        panel.SetSizer(sizer)
        self._mgr.AddPane(panel, wx.aui.AuiPaneInfo().
                          Name("host_tree").Caption("Hosts").
                          Left().
                          Layer(1).
                          Position(1).
                          CloseButton(False).
                          MaximizeButton(True).
                          BestSize((200,250))
                          )
        self.tree = tree

    def CreateTextCtrl(self, font="Courier New"):
        tc = wx.TextCtrl(self, -1, "", wx.Point(0, 0), wx.Size(150, 90),
                wx.NO_BORDER | wx.TE_MULTILINE | wx.TE_READONLY)
#                wx.NO_BORDER | wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_DONTWRAP)
        tc.SetFont(wx.Font(10, wx.DEFAULT, wx.NORMAL, wx.NORMAL, False, font))
        return tc

    def add_display_pane(self):
        notebook = wx.aui.AuiNotebook(self)
        self.notebook = notebook
        display = self.CreateTextCtrl()
        display.SetFont(wx.Font(10, wx.DEFAULT, wx.NORMAL, wx.NORMAL, False, "Courier New"))
        self.display = display

        notebook.AddPage(display, "Output")
        self._mgr.AddPane(notebook, wx.aui.AuiPaneInfo().
                          Name("display").Caption("Output").
                          CenterPane().MaximizeButton(True))

    def add_toolbars(self):
        bar = wx.ToolBar(self, -1, wx.DefaultPosition, wx.DefaultSize,
                         wx.TB_FLAT | wx.TB_NODIVIDER | wx.TB_HORZ_TEXT)
        bar.SetToolBitmapSize(wx.Size(16,16))
        bar_bmp1 = wx.ArtProvider_GetBitmap(wx.ART_NORMAL_FILE, wx.ART_OTHER, wx.Size(16, 16))
        bar.AddLabelTool(ID_Load_Files, "Open Files...", bar_bmp1)
        bar.AddLabelTool(ID_Merge_Files, "Merge Files", bar_bmp1)
        #bar.AddLabelTool(ID_Generate_CSV, "Generate CSV...", bar_bmp1)
        #bar.AddLabelTool(ID_Generate_VulnXML, "Generate VulnXML...", bar_bmp1)
        #bar.AddLabelTool(ID_Generate_RST, "Generate RST...", bar_bmp1)
        bar.Realize()

        self._mgr.AddPane(bar, wx.aui.AuiPaneInfo().
                          Name("toolbar").Caption("Toolbar").
                          ToolbarPane().Top().Row(1).
                          LeftDockable(True).RightDockable(False))

    def add_menubar(self):
        mb = wx.MenuBar()
        file_menu = wx.Menu()
        file_menu.Append(wx.ID_OPEN, "&Open Files\tCtrl+O")
        file_menu.AppendSeparator()
        file_menu.Append(wx.ID_EXIT, "E&xit")
        options_menu = wx.Menu()
        options_menu.Append(ID_Generate_CSV, "CSV...")
        options_menu.Append(ID_Generate_VulnXML, "VulnXml...")
        options_menu.Append(ID_Generate_RST, "ReStructured Text...")

        export_menu = wx.Menu()
        export_menu.AppendMenu(wx.ID_ANY, "&All issues...", options_menu)
        help_menu = wx.Menu()
        help_menu.Append(ID_About, "About...")
        mb.Append(file_menu, "File")
        mb.Append(export_menu, "Export")
        mb.Append(help_menu, "Help")
        self.SetMenuBar(mb)

    def set_statusbar(self):
        self.statusbar.SetStatusWidths([-2, -3])
        self.statusbar.SetStatusText("Ready to view those nessus files!", 0)
        self.statusbar.SetStatusText("Welcome To NessusViewer!", 1)

    def set_size(self):
        self.SetSize((800, 500))
