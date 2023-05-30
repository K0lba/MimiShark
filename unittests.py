import unittest
import dpkt
from pcap_parser import add_packets, ip_protocol_prop

class TestParser(unittest.TestCase):

    def setUp(self):
        self.parser = add_packets
        self.ip_prop = ip_protocol_prop
        self.pcap = dpkt.pcap.Reader(open('temp/testsforparser.pcap','rb'))
        self.ip = "bad ip"

    def test_parser(self):
        self.assertEqual(self.parser(self.pcap)[0]["length"], 52)

    def test_prot_prop(self):
        self.assertEqual(self.ip_prop(self.ip), "No protocol")
  
if __name__ == "__main__":
    unittest.main()