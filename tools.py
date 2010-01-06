# Nessus results viewing tools
#
# Developed by Felix Ingram, f.ingram@gmail.com, @lllamaboy
# http://www.github.com/nccgroup/nessusviewer
#
# Released under AGPL. See LICENSE for more information

from xml.etree import ElementTree as ET

from CmdLineApp.CmdLineApp import CommandLineApp, OptionDef, BoolOpt

class Host():
    def __init__(self, element):
        self._element = element
        self.items = [Item(i) for i in element.findall("ReportItem")]
        self.address = element.find("HostName").text

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

class Item():
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

def get_hosts(tree):
    return [Host(h) for h in tree.findall("Report/ReportHost")]

def find_host(tree, host):
    return [Host(h) for h in tree.findall("Report/ReportHost") if h.find("HostName").text == host][0]

def find_nessus_id(tree, id_):
    return [Item(i) for i in tree.findall("Report/ReportHost/ReportItem") if i.find("pluginID").text == str(id_)]

def hosts_with_id(tree, id_):
    hosts = tree.findall("Report/ReportHost")
    ret = []
    for h in hosts:
        items = [i for i in h.findall("ReportItem") if i.find("pluginID").text == str(id_)]
        if items:
            ret.append(Host(h))
    return ret

def find_shares(tree):
    hosts = hosts_with_id(tree, 10396)
    shares = []
    for host in hosts:
        h_shares = [i for i in host.items if i.pid == 10396][0].output.split("The following shares can be accessed")[1]
        shares.append((host, h_shares.split("\\n\\n")[1].split("\\n")))
    return shares

def find_high_med(tree):
    hosts = get_hosts(tree)
    ret = []
    for host in hosts:
        issues = [i for i in host.items if i.severity > 1]
        if issues:
            ret.append((host, issues))
    ret.sort()
    return ret

class NessusTools(CommandLineApp):
    plugin_slice = BoolOpt("-p", "--plugin-slice", dest="slice", help="Slice the file by plugins")
    make_otl = BoolOpt("--outline", dest="otl", help="Output in OTL format")
    highs = BoolOpt("--highs", dest="highs", help="Output high issues")
    meds = BoolOpt("--meds", dest="meds", help="Output medium issues")
    lows = BoolOpt("--lows", dest="lows", help="Output low issues")
    nessus_file = OptionDef("-i", "--input", dest="input", action="store", help="Nessus file to parse")

    def main(self):
        if not self.options.input:
            self.error("Need a file to parse")
            self.exit()
        self.parse_file()
        if self.options.slice:
            self.debug("Slicing by plugin")
            self.slice_by_plugin()
        else:
            self.error("You probably want -p at the moment")

    def parse_file(self):
        self.tree = ET.parse(self.options.input).getroot()

    def slice_by_plugin(self):
        pids = self.get_pids()
        for pid in pids:
            plugin = [Item(i) for i in self.tree.findall("Report/ReportHost/ReportItem") if i.find("pluginID").text == str(pid)][0]
            hosts = self.hosts_with_id(pid, sort=True)
            if hosts:
                if self.options.otl:
                    self.output("\t[_]", plugin)
                    self.output("\t\t:", "\n\t\t: ".join(plugin.output.split("\\n")))
                    self.output("\t\tHosts")
                    for host in self.hosts_with_id(pid, sort=True):
                        self.output("\t\t\t:", host)
                else:
                    self.output(plugin)
                    self.output("\n".join(plugin.output.split("\\n")))
                    self.output("Hosts")
                    for host in self.hosts_with_id(pid, sort=True):
                        self.output(host)

    def get_pids(self):
        pids = [Item(i).pid for i in self.tree.findall("Report/ReportHost/ReportItem")]
        pids.sort()
        return list(set(pids))

    def check_plugin_level(self, item):
        sev = item.severity
        if self.options.highs and sev == 3:
            self.debug("Item was high")
            return True
        elif self.options.meds and sev == 2:
            return True
        elif self.options.lows and sev == 1:
            return True
        elif self.options.highs or self.options.meds or self.options.lows:
            self.debug("An option was set but the plugin didn't match so we're false")
            return False
        self.debug("No options set we're true")
        return True

    def hosts_with_id(self, id_, sort=False):
        hosts = get_hosts(self.tree)
        if sort:
            hosts.sort()
        ret = []
        for h in hosts:
            items = [i for i in h.items if i.pid == id_ and self.check_plugin_level(i)]
            if items:
                ret.append(h)
        return ret

if __name__ == '__main__':
    app = NessusTools()
    app.run()
