#cloud-config
users:
  - default
  - name: fcsqa
    gecos: FCS QA
    primary_group: fcsqa
    groups: adm, wheel
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${bastion_public_key}
      - ${test_user_public_key}
package_update: true
packages:
  - nginx
  - iperf3
  - tcpreplay
  - nmap
runcmd:
  - service nginx restart
