import dpkt
import datetime
import json
from dpkt.utils import mac_to_str, inet_to_str
from dpkt import iteritems, Packet
import subprocess

def ip_protocol_prop(self, indent=1):
    try:
        self._create_public_fields()
    except:
        return 'No protocol'

    l_ = []

    def add_field(fn, fv):
        if(fn == 'sum'):
            l_.append('%s=%s' % (fn, fv))
        else:
            l_.append('%s=%s,' % (fn, fv))

    for field_name in self.__public_fields__:
        if isinstance (self, dpkt.tcp.TCP):

            tcp = self
            d = {dpkt.tcp.TH_FIN:'FIN', dpkt.tcp.TH_SYN:'SYN', dpkt.tcp.TH_RST:'RST', dpkt.tcp.TH_PUSH:'PUSH', dpkt.tcp.TH_ACK:'ACK', dpkt.tcp.TH_URG:'URG'}

            active_flags = filter(lambda t: t[0] & tcp.flags, d.items())
            flags_str = ' + '.join(t[1] for t in active_flags)

            flag = f'({str(flags_str)})'
        if not("src" == field_name or "dst" == field_name or "urp" == field_name or "group" == field_name):
            if("sport" == field_name):
                add_field("sourceport", getattr(self, field_name))
                continue
            if("dport" == field_name):
                add_field("destinationport", getattr(self, field_name))
                continue
            if("flags" == field_name):
                add_field(field_name, flag)
            else:
                add_field(field_name, getattr(self, field_name))


    ethernet = ' %s(' % self.__class__.__name__  
    for ii in l_:
        ethernet += ' ' * indent + '%s' % ii
    ethernet += ' ' * (indent - 1)+ ''
    ethernet +=' )'
    return ethernet

def add_packets(pcap):
    for  timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if(str(tcp) == "b''"):
            continue
        # print(f" Ethernet Frame:  Destination: {mac_to_str(eth.dst)}  Sourse: {mac_to_str(eth.src)}")#  Type: IPv{ip.v} (0x{eth.type})")
        print(mac_to_str(buf))
        # print(buf)
        # print((bytes.fromhex(mac_to_str(buf).replace(':',''))).decode('UTF-8'))
        # if not isinstance(ip,dpkt.ip6.IP6):
        # print(mac_to_str(eth.type))
        # print(repr(tcp.data))
        # if isinstance (tcp, dpkt.tcp.TCP):

        #     d = {dpkt.tcp.TH_FIN:'FIN', dpkt.tcp.TH_SYN:'SYN', dpkt.tcp.TH_RST:'RST', dpkt.tcp.TH_PUSH:'PUSH', dpkt.tcp.TH_ACK:'ACK', dpkt.tcp.TH_URG:'URG'}

        #     active_flags = filter(lambda t: t[0] & tcp.flags, d.items())
        #     flags_str = ' + '.join(t[1] for t in active_flags)
        #     print( f'({str(flags_str)})')

def Add_Json():
    with open('temp/testsforparser.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        add_packets(pcap)


if __name__ == '__main__':
    Add_Json()