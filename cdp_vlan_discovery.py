from __future__ import print_function

import ssl
import atexit
from pprint import pprint

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl

# Disable SSL certificate verification (for lazy vCenter admins)
sslContext = ssl.create_default_context()
sslContext.check_hostname = False
sslContext.verify_mode = ssl.CERT_NONE

def VSwitchVlans(portgroups):
    _dict = {}
    for pg in portgroups:
        vswitch = _dict.setdefault(pg.spec.vswitchName, set())
        vswitch.add(pg.spec.vlanId)
    return _dict

def VSwitchPorts(vswitch):
    _dict = {}
    for vs in vswitch:
        vswitch = _dict.setdefault(vs.name, set())
        for port in vs.pnic:
            vswitch.add(port)
    return _dict
    
def GetHostsNicDetail(content):
    print("Gathering host network information ...")
    root_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                        [vim.HostSystem],
                                                        True)
    hosts_nic_config = {}
    for host in root_view.view:
        print(host.name)
        if host.config is None:
            print("Unable to get configuration. Is the host offline?")
            continue
        # Gather the ports assigned to each vSwitch
        vs_ports = VSwitchPorts(host.config.network.vswitch)
        # Gather the vlanIds attached to each vSwitch
        vs_vlans = VSwitchVlans(host.config.network.portgroup)
        # Merge our vSwitch nic and vlan information
        vSwitch = {}
        for vs in vs_ports:
            x = vSwitch.setdefault(vs, {})
            vnic_vlans = {p[-6:]: vs_vlans[vs] for p in vs_ports[vs]}
            x.update(vnic_vlans)
        hosts_nic_config[host.name] = (vSwitch)
    root_view.Destroy()
    return hosts_nic_config
    
def GetCDPNeighbors(content):
    print("Gathering CDP neighbor information ...")
    root_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                        [vim.HostSystem],
                                                        True)
    hosts_cdp_neighbors = {}
    for host in root_view.view:
        print(host.name)
        _dict = hosts_cdp_neighbors.setdefault(host.name, {})
        try:
            query = host.configManager.networkSystem.QueryNetworkHint()
        except vmodl.fault.HostNotConnected:
            print("\tUnable to query host. Is the host offline?")
            continue
        for nic in query:
            vmnic = nic.device
            if hasattr(nic.connectedSwitchPort, 'devId'):
                neighbor = nic.connectedSwitchPort.devId
                port = nic.connectedSwitchPort.portId
                _dict[vmnic] = {
                    'neighbor': neighbor,
                    'port': port
                }
            else:
                _dict[vmnic] = None
    root_view.Destroy()
    return hosts_cdp_neighbors


def GetArgs():
    if len(sys.argv) != 4:
        host = raw_input("vCenter IP: ")
        user = raw_input("Username: ")
        password = raw_input("Password: ")
    else:
        host, user, password = sys.argv[1:]
    return host, user, password


def main():
    global content, hosts, hostPgDict
    host, user, password = GetArgs()
    serviceInstance = SmartConnect(host=host,
                                   user=user,
                                   pwd=password,
                                   port=443,
                                   sslContext=sslContext)
    atexit.register(Disconnect, serviceInstance)
    content = serviceInstance.RetrieveContent()
    host_nics = GetHostsNicDetail(content)
    cdp_neighbors = GetCDPNeighbors(content)
    for host in host_nics:
        print(host)
        vSwitches = host_nics[host]
        for vs in vSwitches:
            print("  " + vs)
            for nic in vSwitches[vs]:
                if cdp_neighbors[host][nic] is not None:
                    cdp_neighbor = cdp_neighbors[host][nic]['neighbor']
                    cdp_port = cdp_neighbors[host][nic]['port']
                    print("\t{} is attached to {} port {}".format(nic, cdp_neighbor, cdp_port))
                print("\t{} requires VLANs: {}".format(nic, vSwitches[vs][nic])) 
