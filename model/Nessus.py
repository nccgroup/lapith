# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

from xml.etree import ElementTree as ET
import os

SEVERITY = {0:"Other", 1:"Low", 2:"Med", 3:"High", 4:"Critical"}

NESSUS_VERSIONS = {
        "NessusClientData": "V1",
        "NessusClientData_v2": "V2",
        }

class MergedNessusReport(object):
    def __init__(self, files):
        self._trees = [e._tree for e in files]
        self._files = files
        all_reports = []
        for file_ in self._files:
            for report in file_._tree.findall("Report"):
                all_reports.append(NessusReport(report, file_.version))

        self.criticals = []
        self.highs = []
        self.meds = []
        self.lows = []
        self.others = []

        for report in all_reports:
            self.criticals.extend(report.criticals)
            self.highs.extend(report.highs)
            self.meds.extend(report.meds)
            self.lows.extend(report.lows)
            self.others.extend(report.others)

        self.hosts = []
        for report in all_reports:
            self.hosts.extend([NessusHost(h, report.version) for h in report._element.findall("ReportHost")])
        self.hosts.sort()

    def get_all_reports(self):
        all_reports = []
        for file_ in self._files:
            for report in file_._tree.findall("Report"):
                all_reports.append(NessusReport(report, file_.version))
        return all_reports

    def hosts_with_pid(self, pid):
        ret = []
        for h in self.hosts:
            items = [i for i in h.items if i.pid == pid]
            if items:
                ret.append(h)
        return ret

class NessusFile(object):
    def __init__(self, file_name):
        self._tree = ET.parse(file_name).getroot()
        self.version = NESSUS_VERSIONS[self._tree.tag]
        self.name = file_name
        self.short_name = file_name.split(os.sep)[-1]
        self.reports = [NessusReport(r, self.version) for r in self._tree.findall("Report")]
        items = []
        for r in self.reports:
            items.extend(r.items)
        self.unique_pids = set(i.pid for i in items)

    def get_all_reports(self):
        return [NessusReport(r, self.version) for r in self._tree.findall("Report")]

class NessusTreeItem(object):
    def __init__(self, report, item):
        self.pid = item.pid
        self.report = report
        if self.pid == 0:
            self.name = str(item)
        else:
            self.name = "%s %s" % (self.pid, item.name)
        self.item = item

    def __eq__(self, other):
        return self.pid == other.pid and self.name == other.name

    def __hash__(self):
        return (self.pid, self.name).__hash__()

    def __repr__(self):
        return self.name

class NessusReport(object):
    def __init__(self, element, version):
        self._element = element
        self.version = version
        self.hosts = [NessusHost(h, self.version) for h in self._element.findall("ReportHost")]
        self.hosts.sort()
        self.items = []
        for host in self.hosts:
            self.items.extend(NessusItem(i, self.version, host=host) for i in host._element.findall("ReportItem"))

        self.criticals = [i for i in self.items if i.severity == 4]
        self.criticals.sort(lambda x, y: x.pid-y.pid)

        self.highs = [i for i in self.items if i.severity == 3]
        self.highs.sort(lambda x, y: x.pid-y.pid)

        self.meds = [i for i in self.items if i.severity == 2]
        self.meds.sort(lambda x, y: x.pid-y.pid)

        self.lows = [i for i in self.items if i.severity == 1]
        self.lows.sort(lambda x, y: x.pid-y.pid)

        self.others = [i for i in self.items if i.severity == 0]
        self.others.sort(lambda x, y: x.pid-y.pid)

        self.reportname = self._reportname()
        info = [i for i in self.items if i.pid == 19506]
        if info and info[0] is not None:
            self.info = info[0].output
        else:
            self.info = "NO SCAN INFO"

        policyName = self._element.find("Policy/policyName")
        if policyName is not None:
            policyName = policyName.text
        else:
            policyName = None

        policyComments = self._element.find("Policy/policyComments")
        if policyComments is not None:
            policyComments = policyComments.text
        else:
            policyComments = None

        if any((policyName, policyComments)):
            self.policy = str(policyName) + "\n\n" + str(policyComments)
        else:
            self.policy = None

    def _reportname(self):
        if self.version == "V1":
            name = self._element.find("ReportName")
            if name is not None:
                return name.text
            else:
                return self._element.find("ReportHost/HostName").text
        elif self.version == "V2":
            name = self._element.attrib["name"]
            return name

    def hosts_with_pid(self, pid):
        ret = []
        for h in self.hosts:
            items = [i for i in h.items if i.pid == pid]
            if items:
                ret.append(h)
        return ret

class NessusHost():
    def __init__(self, element, version):
        self._element = element
        self.version = version
        self.items = [NessusItem(i, self.version, host=self) for i in element.findall("ReportItem")]
        if version == "V1":
            self.address = element.find("HostName").text
            try:
                self.dns_name = element.find("dns_name").text.replace("(unknown)", "unknown")
                if self.dns_name and self.dns_name[-1] == ".":
                    self.dns_name = self.dns_name[:-1]
                else:
                    self.dns_name = ""
            except AttributeError:
                self.dns_name = ""
        elif self.version == "V2":
            self.properties = element.findall("HostProperties/tag")
            for tag in self.properties:
                if tag.attrib["name"] == "host-ip":
                    self.address = tag.text
                    break
            try:
                for tag in self.properties:
                    if tag.attrib["name"] == "host-fqdn":
                        self.dns_name = tag.text
                        if self.dns_name and self.dns_name[-1] == ".":
                            self.dns_name = self.dns_name[:-1]
                        else:
                            self.dns_name = ""
                        break
            except AttributeError:
                self.dns_name = ""
        if not hasattr(self, "address"):
            self.address = element.attrib["name"]
        if not hasattr(self, "dns_name"):
            self.dns_name = ""

    def item_for_pid(self, pid):
        items = [i for i in self.items if i.pid == pid]
        return items[0]

    def items_for_pid(self, pid):
        return [i for i in self.items if i.pid == pid]

    def plugin_output(self, pid):
        items = [i for i in self.items if i.pid == pid]
        if items:
            return items[0].output.replace('\\n', "\n")
        return ""

    def __repr__(self):
        if self.address != self.dns_name:
            return "%s (%s)" % (self.address, self.dns_name)
        return "%s" % self.address

    def __eq__(self, other):
        import socket
        try:
            if socket.inet_aton(self.address) == socket.inet_aton(other.address):
                return True
        except socket.error:
            return self.address == other.address
        return False

    def __gt__(self, other):
        import socket
        try:
            if socket.inet_aton(self.address) > socket.inet_aton(other.address):
                return True
        except socket.error:
            return self.address > other.address
        return False

    def __lt__(self, other):
        import socket
        try:
            if socket.inet_aton(self.address) < socket.inet_aton(other.address):
                return True
        except socket.error:
            return self.address < other.address
        return False

class NessusItem():
    def __init__(self, element, version, host):
        self._element = element
        self.version = version
        self.host = host
        if self.version == "V1":
            self.pid = int(element.find("pluginID").text)
            try:
                self.name = element.find("pluginName").text
            except AttributeError:
                self.name = "NO NAME"
            try:
                self.output = element.find("data").text
            except AttributeError:
                self.output = ""
            self.severity = int(element.find("severity").text)
        elif self.version == "V2":
            info_dict = {}
            self.pid = int(element.attrib["pluginID"])
            info_dict["pid"] = self.pid
            try:
                self.name = element.attrib["pluginName"]
            except AttributeError:
                self.name = "NO NAME"
            info_dict["name"] = self.name
            try:
                self.output = ""
                for attrib in ("port", "svc_name", "protocol"):
                    self.output += "%s: %s\n" % (attrib, element.attrib.get(attrib))
                    info_dict[attrib] = element.attrib.get(attrib)
                self.output += "\n"
                for element_name in ("description", "plugin_output",
                        "cvss_vector", "cvss_base_score"):
                    output_element = element.find(element_name)
                    if output_element is not None:
                        info_dict[element_name] = output_element.text
                        self.output += element_name.replace("_", " ").title()+":\n"
                        self.output += output_element.text+"\n\n"
                for identifier in ("cve", "bid", "xref", "see_also",
                        "exploit_available", "stig_severity"):
                    list_ = element.findall(identifier)
                    if list_:
                        info_dict[identifier] = []
                        for item in list_:
                            info_dict[identifier].append(item.text)
                            self.output += identifier.upper()+": "
                            self.output += item.text+"\n"
            except AttributeError:
                self.output = ""
            self.severity = int(element.attrib["severity"])
            self.severity_text = SEVERITY[self.severity]
            info_dict["severity"] = element.attrib["severity"]
            info_dict["severity_text"] = SEVERITY[self.severity]
            self.info_dict = info_dict

    def __repr__(self):
        if self.pid == 0:
            if self.version == "V1":
                return "PORT: %s" % self._element.find("port").text
            elif self.version == "V2":
                return "PORT: %s" % self._element.attrib["port"]
        else:
            return '%s: %s' % (self.pid, self.name)
