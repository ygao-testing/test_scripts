#cloud-config
package_update: true
preserve_hostname: true
packages:
  - wget
  - nmap
  - xmrig
runcmd:
%{ if agentless_scan == "false" }
  - curl ${agent_download_url} -o install.sh
  - sh install.sh
  - echo "Agent installed successfully."
%{ else }
  - echo "Agentless scan is enabled."
%{ endif }
  - hostnamectl set-hostname ${hostname}
