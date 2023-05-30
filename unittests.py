import unittest
from pcap_parser import Add_Json
#Test cases to test Calulator methods
#You always create  a child class derived from unittest.TestCase
class TestParser(unittest.TestCase):
  #setUp method is overridden from the parent class TestCase
  def setUp(self):
    self.calculator = Add_Json
  #Each test method starts with the keyword test_
  def test_time(self):
    self.assertEqual((1+10), 11)
  
# Executing the tests in the above test case class
if __name__ == "__main__":
  unittest.main()