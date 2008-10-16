# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

from xml.etree import ElementTree as ET

class NessusFile(object):
    def __init__(self, file_name):
        self._tree = ET.parse(file_name).getroot()
        self.name = file_name

    def GetAllReports(self):
        return [NessusReport(r) for r in self._tree.findall("Report")]

class NessusTreeItem(object):
    def __init__(self, report, item):
        self.pid = item.pid
        self.report = report
        if self.pid == 0:
            self.name = str(item)
        else:
            self.name = "%s %s" % (self.pid, item.name)

    def __eq__(self, other):
        return self.pid == other.pid and self.name == other.name

    def __hash__(self):
        return (self.pid, self.name).__hash__()

    def __repr__(self):
        return self.name

class NessusReport(object):
    def __init__(self, element):
        self._element = element
        self.items = [NessusItem(i) for i in self._element.findall("ReportHost/ReportItem")]

        self.highs = [i for i in self.items if i.severity == 3]
        self.highs.sort(lambda x, y: x.pid-y.pid)

        self.meds = [i for i in self.items if i.severity == 2]
        self.meds.sort(lambda x, y: x.pid-y.pid)

        self.lows = [i for i in self.items if i.severity == 1]
        self.lows.sort(lambda x, y: x.pid-y.pid)

        self.others = [i for i in self.items if i.severity == 0]
        self.others.sort(lambda x, y: x.pid-y.pid)

        self.reportname = self._reportname()
        self.info = [i for i in self.items if i.pid == 19506][0].output
        self.hosts = [NessusHost(h) for h in self._element.findall("ReportHost")]
        self.hosts.sort()

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
            self.policy = policyName + "\n\n" + policyComments
        else:
            self.policy = None
    
    def _reportname(self):
        name = self._element.find("ReportName")
        if name is not None:
            return name.text
        else:
            return self._element.find("ReportHost/HostName").text

    def hosts_with_pid(self, pid):
        ret = []
        for h in self.hosts:
            items = [i for i in h.items if i.pid == pid]
            if items:
                ret.append(h)
        return ret

class NessusHost():
    def __init__(self, element):
        self._element = element
        self.items = [NessusItem(i) for i in element.findall("ReportItem")]
        self.address = element.find("HostName").text
        self.dns_name = element.find("dns_name").text

    def plugin_output(self, pid):
        items = [i for i in self.items if i.pid == pid]
        if items:
            return items[0].output.replace('\\n', "\n")
        return ""

    def __repr__(self):
        return self._element.find("HostName").text

    def __eq__(self, other):
        from socket import inet_aton
        if inet_aton(self.address) == inet_aton(other.address):
            return True
        return False

    def __gt__(self, other):
        from socket import inet_aton
        if inet_aton(self.address) > inet_aton(other.address):
            return True
        return False

    def __lt__(self, other):
        from socket import inet_aton
        if inet_aton(self.address) < inet_aton(other.address):
            return True
        return False

class NessusItem():
    def __init__(self, element):
        self._element = element
        self.pid = int(element.find("pluginID").text)
        self.name = element.find("pluginName").text
        self.output = element.find("data").text
        self.severity = int(element.find("severity").text)

    def __repr__(self):
        if self.pid == 0:
            return "PORT: %s" % self._element.find("port").text
        else:
            return '%s: %s' % (self.pid, self.name)
