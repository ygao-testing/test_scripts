import paramiko
import logging
import time

logger = logging.getLogger(__name__)


class SSHHelper:
    def __init__(self, hostname: str, username: str, password: str = '', key_filename: str = ''):
        """
        Initialize SSH connection to the remote host with retry logic.
        Args:
            hostname: Remote host IP or hostname
            username: SSH username
            password: SSH password (optional if using key)
            key_filename: SSH private key file path (optional)
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        attempt = 0
        while attempt < 3:
            try:
                self.ssh.connect(hostname, username=username, password=password, key_filename=key_filename)
                return
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} to connect to {hostname} failed: {str(e)}")
                attempt += 1
                if attempt < 3:
                    time.sleep(5)
                else:
                    raise e
        logger.error(f"Failed to connect to {hostname} after 3 attempts.")

    def execute_command(self, command: str):
        """
        Execute a command on the remote host.
        Args:
            command: Command string to execute
        Returns:
            stdout, stderr as strings
        Raises:
            Exception if command execution fails
        """
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            out = stdout.read().decode()
            err = stderr.read().decode()
            if err:
                logger.error(f"Error executing command '{command}': {err}")
                raise Exception(f"Error executing command '{command}': {err}")
            return out, err
        except Exception as e:
            logger.error(f"Failed to execute command '{command}' on {self.hostname}: {str(e)}")
            raise

    def get_remote_file_content(self, filepath: str, use_sudo: bool = False) -> str:
        """
        Safely retrieve content from a remote file using SSH, handling first-time connections
        and permission issues.
        Args:
            filepath: Full path to the remote file
            use_sudo: Whether to use sudo to read the file
        Returns:
            str: Content of the remote file
        Raises:
            Exception: If unable to retrieve the file content
        """
        # Use sudo if needed to read the file
        command = f"sudo cat {filepath}" if use_sudo else f"cat {filepath}"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            err = stderr.read().decode().strip()
            if err:
                logger.error(f"Error reading file {filepath}: {err}")
                raise Exception(f"Failed to read remote file: {err}")
            content = stdout.read().decode()
            return content
        except Exception as e:
            logger.error(f"Failed to retrieve remote file {filepath} from {self.hostname}: {str(e)}")
            raise

    def upload_file(self, local_path: str, remote_path: str, mode: int = 0o644):
        """
        Upload a file to the remote host using SFTP.
        Args:
            local_path: Path to the local file
            remote_path: Path on the remote host
            mode: File mode/permissions to set (default 0o644)
        """
        try:
            sftp = self.ssh.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.chmod(remote_path, mode)
            sftp.close()
        except Exception as e:
            logger.error(f"Failed to upload {local_path} to {remote_path} on {self.hostname}: {str(e)}")
            raise
