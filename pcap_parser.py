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


    ip_prot = ' %s: ' % self.__class__.__name__  
    for ii in l_:
        ip_prot += ' ' * indent + '%s' % ii
    # ip_prot += ' ' * (indent - 1)+ ''
    # ip_prot +=' '
    return ip_prot


json_file = []


def add_packets(pcap):
    with open("pcap.json","w") as file:
        for  timestamp, buf in pcap:
            pcap_file = {}
            eth = dpkt.ethernet.Ethernet(buf)
            # print('Ethernet Frame: ', mac_to_str(eth.src), mac_to_str(eth.dst), eth.type)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            
            
            pcap_file["time"] = str(datetime.datetime.utcfromtimestamp(timestamp))

            ip = eth.data
            pcap_file["source"] = inet_to_str(ip.src)
            pcap_file["destination"] = inet_to_str(ip.dst)
            pcap_file["protocol"] = ip.get_proto(ip.p).__name__
            pcap_file["length"] = ip.len

            icmp = ip.data
            string = repr(icmp.data)
            temp  =[]
            for b in string.split('\\x'):
                if(b=="b'"):
                    continue
                if(len(b)==2):
                    temp.append('.')
                    continue
                temp.append(b[2:].replace("'",''))
            ascii = "".join(temp)
            # .replace('"',"'").replace('\\',"|").replace("'",'')
            # pcap_file["ascii"] = ascii

            bytes_repr = ' '.join(mac_to_str(buf).split(':'))
            ascii = ''
            for i in bytes_repr.split(' '):
                a = bytes.fromhex(i)
                b = str(a)[2:len((str(a)))-1]
                if(len(b)<2):
                    ascii += b
                else:
                    ascii+= '.'
            pcap_file["ascii"] = ascii.replace('"','doublePrime').replace("'",'singlePrime')

            byte = repr(icmp.data).replace('\\','').replace('"',"").replace("b'","").replace("'","").replace('x',' ').replace('A','').split(' ')
            temp = []
            for i in byte:
                if(len(i)<2):
                    continue
                
                temp.append(i[:2])
            hex = ''.join(temp)
            temp = " ".join(temp)
            if(temp == ""):
                temp = "no data"

            # pcap_file["bytes"] = temp
            pcap_file["bytes"] = bytes_repr
            # decode = pprint(eth).replace('\\','|').replace("'","").replace('"','')
            pcap_file["decode_eth"] = f" Ethernet Frame:  Destination: {mac_to_str(eth.dst)}  Sourse: {mac_to_str(eth.src)}  Type: IPv{ip.v} (0x{bytes_repr[36:41].replace(' ','')})"
            pcap_file["decode_ip"] = ip_protocol_prop(ip)
            pcap_file[f"decode_{ip.data.__class__.__name__}"] = ip_protocol_prop(ip.data)
            json_file.append(pcap_file)
        print(json.dumps(json_file), file=file)


def Add_Json():
    with open('temp/testsforparser.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        add_packets(pcap)


if __name__ == '__main__':
    Add_Json()
