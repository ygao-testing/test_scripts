#cloud-config
users:
  - name: fcsqa
    gecos: FCS QA
    primary_group: fcsqa
    groups: adm, wheel
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
package_update: true
packages:
  - wget
  - nmap
runcmd:
  - mkdir /opt/java/
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j-core-2.12.1.jar -o /opt/java/log4j-core-2.12.1.jar
  - curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
  - dpkg -i session-manager-plugin.deb
  - curl ${agent_download_url} -o install.sh
  - sh install.sh
  - echo "Agent installed successfully."
