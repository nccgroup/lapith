# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

from CmdLineApp import GUIApp
import wx
import os
from model import NessusFile, NessusTreeItem, MergedNessusReport, NessusReport
import difflib

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
        self.view.tree.AddRoot("Scans")

        self.create_scan_trees()
        self.view.tree.Expand(self.view.tree.GetRootItem())

    def create_scan_trees(self):
        scans = self.view.tree.GetRootItem()

        for file_ in self.files:
            self.create_scan_tree(file_, scans)
        self.view.tree.Expand(scans)

    def sorted_tree_items(self, report, items):
        list_ = list(set([NessusTreeItem(report, i) for i in items]))
        list_.sort()
        return list_
        
    def create_scan_tree(self, file_, hosts):
        reports = file_.GetAllReports()
        scans_hook = self.view.tree.GetRootItem()
        file_hook = self.view.tree.AppendItem(scans_hook, file_.short_name, 0)

        for report in reports:
            scan = self.view.tree.AppendItem(file_hook, report.reportname, 0)
            self.view.tree.SetPyData(scan, report)

            info = self.view.tree.AppendItem(scan, "Info", 0)
            self.view.tree.SetPyData(info, report.info)

            if report.policy:
                policy = self.view.tree.AppendItem(scan, "Policy", 0)
                self.view.tree.SetPyData(policy, report.policy)

            hosts = self.view.tree.AppendItem(scan, "Hosts", 0)
            self.view.tree.SetPyData(hosts, "\n".join(str(h) for h in report.hosts))

            items_hook = self.view.tree.AppendItem(scan, "Findings", 0)
            self.view.tree.SetPyData(items_hook, self.sorted_tree_items(report, report.highs+report.meds+report.lows+report.others))
            high_hook = self.view.tree.AppendItem(items_hook, "Highs", 0)
            self.view.tree.SetPyData(high_hook, self.sorted_tree_items(report, report.highs))
            med_hook = self.view.tree.AppendItem(items_hook, "Meds", 0)
            self.view.tree.SetPyData(med_hook, self.sorted_tree_items(report, report.meds))
            low_hook = self.view.tree.AppendItem(items_hook, "Lows", 0)
            self.view.tree.SetPyData(low_hook, self.sorted_tree_items(report, report.lows))
            other_hook = self.view.tree.AppendItem(items_hook, "Others", 0)
            self.view.tree.SetPyData(other_hook, self.sorted_tree_items(report, report.others))
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

    def get_item_output(self, item):
        hosts = item.report.hosts_with_pid(item.pid)

        initial_output = hosts[0].plugin_output(item.pid)
        diffs = []
        for host in hosts[1:]:
            diff = difflib.unified_diff(initial_output.splitlines(), host.plugin_output(item.pid).splitlines())
            diffs.append((host, "\n".join(list(diff))))
        initial_output = item.name.strip() + "\n\n" + initial_output

        diff_output = ""

        identical_hosts = [hosts[0]]
        for (host, diff) in diffs:
            if diff:
                diff_output += "=" * 70 + "\n\n%s\n%s\n\n" % (host, diff)
            else:
                identical_hosts.append(host)
        output = item.name+"\n"
        output += "%s hosts with this issue\n" % len(hosts)
        output += "\n".join(str(i) for i in hosts)
        output += "\n"+"-"*20+"\n"
        output += "\n".join(str(i) for i in identical_hosts) + "\n\n" + initial_output
        return output, diff_output

    def ShowNessusItem(self, item):
        output, diff_output = self.get_item_output(item)

        diff_title = "Diffs"
        self.DeletePageWithTitle(diff_title)

        display = self.view.display
        if diff_output:
            self.AddOutputPage(diff_title, diff_output, font="Courier New")
        display.SetValue(output)

    def combine_files(self):
        scans_hook = self.view.tree.GetRootItem()
        merged_scans = MergedNessusReport(self.files)

        if merged_scans.GetAllReports():
            merge_hook = self.view.tree.AppendItem(scans_hook, "Merged Files", 0)

            items_hook = self.view.tree.AppendItem(merge_hook, "Findings", 0)
            self.view.tree.SetPyData(items_hook, self.sorted_tree_items(merged_scans, merged_scans.highs+merged_scans.meds+merged_scans.lows+merged_scans.others))

            high_hook = self.view.tree.AppendItem(items_hook, "Highs", 0)
            self.view.tree.SetPyData(high_hook, self.sorted_tree_items(merged_scans, merged_scans.highs))

            med_hook = self.view.tree.AppendItem(items_hook, "Meds", 0)
            self.view.tree.SetPyData(med_hook, self.sorted_tree_items(merged_scans, merged_scans.meds))

            low_hook = self.view.tree.AppendItem(items_hook, "Lows", 0)
            self.view.tree.SetPyData(low_hook, self.sorted_tree_items(merged_scans, merged_scans.lows))

            other_hook = self.view.tree.AppendItem(items_hook, "Others", 0)
            self.view.tree.SetPyData(other_hook, self.sorted_tree_items(merged_scans, merged_scans.others))

            for high in self.sorted_tree_items(merged_scans, merged_scans.highs):
                item = self.view.tree.AppendItem(high_hook, str(high), 0)
                self.view.tree.SetPyData(item, high)
            for med in self.sorted_tree_items(merged_scans, merged_scans.meds):
                item = self.view.tree.AppendItem(med_hook, str(med), 0)
                self.view.tree.SetPyData(item, med)
            for low in self.sorted_tree_items(merged_scans, merged_scans.lows):
                item = self.view.tree.AppendItem(low_hook, str(low), 0)
                self.view.tree.SetPyData(item, low)
            for other in merged_scans.others:
                item = self.view.tree.AppendItem(other_hook, str(other), 0)
                self.view.tree.SetPyData(item, other)
            self.view.tree.Expand(scans_hook)

    def tree_menu_click(self, data):
        saveas = self.view.SaveDialog(remember=True, message="Save results as...")
        if saveas:
            with open(saveas, "w") as f:
                output = ""
                if isinstance(data, list):
                    for item in data:
                        output, diff_output = self.get_item_output(item)
                        f.write("="*20+"\n")
                        f.write(output)
                        f.write(diff_output)
                elif isinstance(data, NessusReport):
                    pass
                elif isinstance(data, MergedNessusReport):
                    pass
