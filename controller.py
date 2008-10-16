# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

from CmdLineApp import GUIApp
from glob import glob
import wx
import os
from model import NessusFile, NessusTreeItem
import inspect

#Used to let us know what a test function looks like
TEST_IDENT = "WP_AIX"

class ViewerController(GUIApp.GUIController):
    def initView(self):
        self.files = []
        self.tests = []
        self.tree_hooks = {}
        self.view.app.SetTopWindow(self.view)
        self.create_tree()
        self.view.Show()
        return True

    def AddOutputPage(self, title, text, font="Courier New"):
        display = self.view.CreateTextCtrl(font=font)
        display.SetValue(text)
        self.DeletePageWithTitle(title)
        self.view.notebook.AddPage(display, title)
        return self.view.notebook.GetPageIndex(display)

    def LoadFiles(self):
        wildcard = "Nessus files (*.nessus)|*.nessus|"     \
                   "All files (*.*)|*.*"

        dlg = wx.FileDialog(
                self.view, message="Choose a file",
                defaultDir=os.getcwd(), 
                defaultFile="",
                wildcard=wildcard,
                style=wx.OPEN | wx.MULTIPLE | wx.CHANGE_DIR
                )
        if dlg.ShowModal() == wx.ID_OK:
            # This returns a Python list of files that were selected.
            paths = dlg.GetPaths()

            for path in paths:
                self.files.append(NessusFile(path))
        dlg.Destroy()
        self.create_scan_trees()

    def DeletePageWithTitle(self, title):
        notebook = self.view.notebook
        page_count = notebook.GetPageCount()
        for i in xrange(page_count):
            if notebook.GetPageText(i) == title:
                notebook.DeletePage(i)

    def create_tree(self):
        self.view.tree.DeleteAllItems()
        self.view.tree.AddRoot("Viewer")

        self.create_scan_trees()
        self.view.tree.Expand(self.view.tree.GetRootItem())

    def create_scan_trees(self):
        if "scans" in self.tree_hooks:
            self.view.tree.Delete(self.tree_hooks["scans"])
        root = self.view.tree.GetRootItem()
        scans = self.view.tree.AppendItem(root, "Scans", 0)
        self.tree_hooks["scans"] = scans

        for file_ in self.files:
            self.create_scan_tree(file_, scans)
        self.view.tree.Expand(scans)

    def sorted_tree_items(self, report, items):
        list_ = list(set([NessusTreeItem(report, i) for i in items]))
        list_.sort()
        return list_
        
    def create_scan_tree(self, file_, hosts):
        reports = file_.GetAllReports()
        scans_hook = self.tree_hooks["scans"]

        for report in reports:
            scan = self.view.tree.AppendItem(scans_hook, report.reportname, 0)
            self.view.tree.SetPyData(scan, report)

            info = self.view.tree.AppendItem(scan, "Info", 0)
            self.view.tree.SetPyData(info, report.info)

            if report.policy:
                policy = self.view.tree.AppendItem(scan, "Policy", 0)
                self.view.tree.SetPyData(policy, report.policy)

            hosts = self.view.tree.AppendItem(scan, "Hosts", 0)
            self.view.tree.SetPyData(hosts, "\n".join(str(h) for h in report.hosts))

            items_hook = self.view.tree.AppendItem(scan, "Findings", 0)
            high_hook = self.view.tree.AppendItem(items_hook, "Highs", 0)
            med_hook = self.view.tree.AppendItem(items_hook, "Meds", 0)
            low_hook = self.view.tree.AppendItem(items_hook, "Lows", 0)
            other_hook = self.view.tree.AppendItem(items_hook, "Others", 0)
            for high in self.sorted_tree_items(report, report.highs):
                item = self.view.tree.AppendItem(high_hook, str(high), 0)
                self.view.tree.SetPyData(item, high)
            for med in self.sorted_tree_items(report, report.meds):
                item = self.view.tree.AppendItem(med_hook, str(med), 0)
                self.view.tree.SetPyData(item, med)
            for low in self.sorted_tree_items(report, report.lows):
                item = self.view.tree.AppendItem(low_hook, str(low), 0)
                self.view.tree.SetPyData(item, low)
            for other in [NessusTreeItem(report, o) for o in report.others]:
                item = self.view.tree.AppendItem(other_hook, str(other), 0)
                self.view.tree.SetPyData(item, other)

    def ShowNessusItem(self, item):
        import difflib
        diff_title = "Diffs"
        self.DeletePageWithTitle(diff_title)

        display = self.view.display
        hosts = item.report.hosts_with_pid(item.pid)

        initial_output = item.name.strip() + "\n\n" + hosts[0].plugin_output(item.pid)
        diffs = []
        for host in hosts[1:]:
            diff = difflib.unified_diff(initial_output.splitlines(), host.plugin_output(item.pid).splitlines())
            diffs.append((host, "\n".join(list(diff))))

        identical_hosts = [hosts[0]]
        output = ""
        for (host, diff) in diffs:
            if diff:
                output += "=" * 70 + "\n\n%s\n%s\n\n" % (host, diff)
            else:
                identical_hosts.append(host)
        if output:
            self.AddOutputPage(diff_title, output, font="Courier New")
        output = ", ".join(str(i) for i in identical_hosts) + "\n\n" + initial_output
        display.SetValue(output)
