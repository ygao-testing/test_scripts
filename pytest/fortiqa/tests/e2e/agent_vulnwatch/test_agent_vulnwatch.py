import logging
import pytest
import os
import time
from fortiqa.libs.helper.ssh_helper import SSHHelper

logger = logging.getLogger(__name__)


def test_vulnwatch_agent(api_v1_client, os_version, agent_host, agent_host_tf_output):
    """
    Test VulnWatch Agent with hello_world binary in Docker

    Args:
        api_v1_client: API v1 client fixture for Lacework backend.
        os_version: OS version string (fixture, e.g., 'ubuntu20.04', 'alpine3.19').
        agent_host: Host information for the deployed agent (fixture).
        agent_host_tf_output: Terraform output for the agent host (fixture).

    Given:
        - A deployed agent host with Lacework agent installed
        - The hello_world binary is available on the test machine
        - Docker is available on the agent host
    When:
        - The hello_world binary is copied into a Docker container and executed
        - The datacollector service is stopped and restarted as needed
        - VulnWatch agent is triggered by running the binary
    Then:
        - The probe hit log message is found in datacollector logs
        - The test passes if the expected vulnerability detection message is present
        - The test fails if any step does not complete as expected
    """
    if os_version == "alpine3.19":
        pytest.xfail(reason="Alpine is not supported by Vuln Dashboard")
    logger.info(f'test_vulnwatch_agent({os_version=})')
    public_ip = agent_host_tf_output['agent_host_public_ip']
    ssh_user = 'fcsqa'
    local_hello_world = os.path.join(os.path.dirname(__file__), 'testdata', 'hello_world')
    remote_hello_world = f"/home/{ssh_user}/hello_world"
    docker_container = 'vulnwatch_test'
    VW_DOCKER_PULL_CMD = "sudo docker pull ubuntu:22.04"
    VW_DOCKER_RUN_CMD = f"sudo docker run -dit --name {docker_container} ubuntu:22.04"
    VW_DOCKER_COPY_TARGET = f"sudo docker cp {remote_hello_world} {docker_container}:/hello_world"
    VW_DOCKER_EXEC_CMD = f"sudo docker exec {docker_container} /hello_world"
    VW_TICKER_MESSAGE = "vulnwatcher: ticker start"
    VW_STARTUP_MESSAGE = "vulnwatcher: starting"
    VW_INSTALLED_MESSAGE = "vulnwatcher: installed {uprobe /hello_world n/a 542455f9ebf7383bfe18147718610786b9cd46dda977ce8f76fdb32e2f33a618 n/a 596608 FTNT-hello-world-test uprobe_alert}"
    VW_HIT_MESSAGE = "vulnwatcher: active vulnerability detected {Kind:uprobe Path:/hello_world BuildId:n/a Hash:542455f9ebf7383bfe18147718610786b9cd46dda977ce8f76fdb32e2f33a618 Symbol:n/a Offset:596608 VulnId:FTNT-hello-world-test Action:uprobe_alert}"

    def wait_for_log(ssh, log_path, target, timeout=120):
        """Wait for a log line containing target string."""
        start = time.time()
        while time.time() - start < timeout:
            out, _ = ssh.execute_command(f'sudo grep "{target}" {log_path}')
            if target in out:
                return True
            time.sleep(10)
        return False

    try:
        ssh = SSHHelper(public_ip, ssh_user)
        # Wait for agent install success log
        logger.info('Waiting for cloud-init script to complete')
        assert wait_for_log(ssh, '/var/log/cloud-init-output.log', "Agent installed successfully."), 'Agent installed successfully message not found'
        # 1. Stop datacollector
        logger.info('Stopping datacollector service')
        ssh.execute_command('sudo systemctl stop datacollector')  # Stop datacollector
        # 2. Pull and run Docker container
        logger.info('Pulling Docker image ubuntu:22.04')
        ssh.execute_command(VW_DOCKER_PULL_CMD)  # Pull Docker image
        logger.info(f'Running Docker container: {docker_container}')
        ssh.execute_command(VW_DOCKER_RUN_CMD)  # Run Docker container
        # 3. Upload hello_world binary to remote
        logger.info('Uploading hello_world binary to remote host')
        ssh.upload_file(local_hello_world, remote_hello_world, mode=0o755)  # Upload hello_world binary
        # 4. Copy binary into container
        logger.info('Copying hello_world binary into container')
        ssh.execute_command(VW_DOCKER_COPY_TARGET)  # Copy binary into container
        # 5. Restart datacollector
        logger.info('Starting datacollector service')
        ssh.execute_command('sudo systemctl start datacollector')  # Start datacollector
        # 6. Wait for ticker message
        logger.info('Waiting for ticker start log message')
        assert wait_for_log(ssh, '/var/log/lacework/datacollector.log', VW_TICKER_MESSAGE), 'Ticker message not found'
        # 7. Wait for startup message
        logger.info('Waiting for startup log message')
        assert wait_for_log(ssh, '/var/log/lacework/datacollector.log', VW_STARTUP_MESSAGE), 'Startup message not found'
        # 8. Wait for probe installed
        logger.info('Waiting for probe installed log message')
        assert wait_for_log(ssh, '/var/log/lacework/datacollector.log', VW_INSTALLED_MESSAGE), 'Probe install message not found'
        # 9. Run hello_world in container
        logger.info('Running hello_world binary inside container')
        ssh.execute_command(f'{VW_DOCKER_EXEC_CMD} &')  # Run hello_world in container
        # 10. Wait for probe to be hit
        logger.info('Waiting for probe hit log message')
        assert wait_for_log(ssh, '/var/log/lacework/datacollector.log', VW_HIT_MESSAGE), 'Probe hit message not found'

        logger.info('Test VulnWatch agent completed successfully')
    except Exception as e:
        logger.error(f"Failed to test VulnWatch agent: {str(e)}")
    finally:
        try:
            ssh.ssh.close()
        except Exception:
            pass
