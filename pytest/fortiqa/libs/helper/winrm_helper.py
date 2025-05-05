import winrm
import time
import logging
import requests

logger = logging.getLogger(__name__)


class WinRmHelper:
    """Helper module to interact with Windows hosts by using Public IP address and password"""

    def __init__(self, ip, password, username="Administrator", port=5985, transport='ntlm'):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.transport = transport
        self._connect()

    def _connect(self, timeout: int = 1800):
        url = f"http://{self.ip}:{self.port}/wsman"
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                self.session = winrm.Session(url, auth=(self.username, self.password), transport=self.transport)
                result = self.session.run_cmd("whoami")
                if result.status_code == 0:
                    logger.info(f"Connected to {self.ip} using {self.transport} transport")
                    return
                else:
                    logger.info(f"Command failed on {self.ip}, retrying...")
            except requests.exceptions.ConnectTimeout:
                logger.warning(f"Connection to {self.ip} timed out. Retrying in 60 seconds...")
            except requests.exceptions.RequestException:
                logger.warning("Request failed. Retrying in 60 seconds...")
            except winrm.exceptions.InvalidCredentialsError:
                logger.warning("Invalid credentials")
            except winrm.exceptions.WinRMTransportError:
                logger.warning("Transport error, retrying in 60 seconds...")
            except Exception:
                logger.warning("Failed to connect, retrying in 60 seconds...")

            time.sleep(60)

        logger.error(f"Timeout reached. Unable to connect to {self.ip}")
        raise TimeoutError(f"Could not connect to {self.ip} within {timeout} seconds")

    def check_cloud_init_status(self) -> str:
        """Function to check cloud-init log, and check if execution done"""
        logger.info("check_cloud_init_status()")
        script = rf"""
            $log_path = "C:\Users\{self.username}\cloud-init\log";
            Get-Content $log_path | Select-String -Pattern "done" | Measure-Object | Select-Object -ExpandProperty Count;
        """
        result = self.session.run_ps(script)
        return result.std_out.decode().strip()

    def get_windows_cloud_init_log(self) -> str:
        """Function to get cloud-init log"""
        logger.info("get_windows_cloud_init_log()")
        script = rf"""
            $log_path = "C:\Users\{self.username}\cloud-init\log";
            Get-Content $log_path;
        """
        result = self.session.run_ps(script)
        return result.std_out.decode().strip()

    def wait_until_cloud_init_finish(self, timeout: int = 1800) -> bool:
        """Continuously checks log file until User Data executed successfully"""
        complete = False
        timed_out = False
        start_time = time.monotonic()
        while not complete and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            count = self.check_cloud_init_status()
            complete = count == "1"
            if complete:
                break
            time.sleep(30)
        if complete:
            logger.info(f"User Data executed successfully. It takes {time_passed} to execute the user data")
            return complete
        else:
            raise TimeoutError("Timed out waiting for user data finishes.")
