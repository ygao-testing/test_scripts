#cloud-config
package_update: true
preserve_hostname: true
runcmd:
  - sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/CentOS-*.repo
  - sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-*.repo
  - sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-*.repo
  - yum update
  - yum install -y nmap
%{ if agentless_scan == "false" }
  - curl ${agent_download_url} -o install.sh
  - sh install.sh
  - echo "Agent installed successfully."
%{ else }
  - echo "Agentless scan is enabled."
%{ endif }
  - hostnamectl set-hostname ${hostname}
