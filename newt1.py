import time
import sys
import logging
import pytest


class TestClass:
    @pytest.fixture(scope="module", autouse=True)
    @classmethod
    def setup_data(cls):
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)
        cls.log = logging.getLogger(__name__)
        cls.log.info("========= test start ========= ")

    @pytest.fixture(autouse=True)
    def setup_teardown_data(self):
        yield
        self.log.info("========= test complete ========= ")

    def test_1(self):
        """
        This is my test case.
        """
        cmd = """
cli
config firewall policy
    edit 1
        set name "Policy for Port4"
        set srcintf "port4"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set nat enable
    next
end
		"""
