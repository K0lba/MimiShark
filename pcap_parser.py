import dpkt
import datetime
import json
from dpkt.utils import mac_to_str, inet_to_str
from dpkt import iteritems, Packet
import subprocess


def pprint(self, indent=1):
    if self.__public_fields__ is None:
        self._create_public_fields()

    l_ = []

    def add_field(fn, fv):

        try:
            l_.append('%s=%r,  # %s' % (fn, fv, self.__pprint_funcs__[fn](fv)))
        except (AttributeError, KeyError):
            l_.append('%s=%r,' % (fn, fv))

    for field_name in self.__public_fields__:
        add_field(field_name, getattr(self, field_name))

    for attr_name, attr_value in iteritems(self.__dict__):
        if (attr_name[0] != '_' and                   
            attr_name != self.data.__class__.__name__.lower()):  
            if type(attr_value) == list and attr_value:  
                l_.append('%s=[' % attr_name)
                for av1 in attr_value:
                    l_.append('  ' + repr(av1) + ',') 
                l_.append('],')
            else:
                add_field(attr_name, attr_value)

    ethernet = ' %s(' % self.__class__.__name__  
    for ii in l_:
        ethernet += ' ' * indent + '%s' % ii

    if self.data:
        if isinstance(self.data, Packet): 
            ethernet += ' ' * indent + 'data='+ ''
            ethernet += pprint(self.data, indent=indent + 2)
            pass
        else:
            ethernet += ' ' * indent + 'data=%r' % self.data
    ethernet += ' ' * (indent - 1)+ ''
    ethernet +=')  # %s' % self.__class__.__name__  
    return ethernet


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
            ascii = "".join(temp).replace('"',"'").replace('\\',"|").replace("'",'')
            pcap_file["ascii"] = ascii

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

            pcap_file["bytes"] = temp
            decode = pprint(eth).replace('\\','|').replace("'","").replace('"','')
            pcap_file["decode_eth"] = f" Ethernet Frame(  Destination: {mac_to_str(eth.dst)}  Sourse: {mac_to_str(eth.src)}  Type: IPv{ip.v} (0x{eth.type}) )"
            # pcap_file["decode_ip"] = 
            # pcap_file[f"decode_{ip.p}"] = 
            json_file.append(pcap_file)
            print(ip.len)
# v=4,
# hl=5,
# tos=0,
# len=173,
# id=58872,
# rf=0,
# df=1,
# mf=0,
# offset=0,
# ttl=128,
# p=6,
        print(json.dumps(json_file), file=file)


def Add_Json():
    with open('temp/testsforparser.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        add_packets(pcap)


if __name__ == '__main__':
    Add_Json()
