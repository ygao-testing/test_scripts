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
      - ${test_user_public_key}
      - ${another_host_public_key}

write_files:
  - content: ${another_host_private_key}
    owner: root:root
    permissions: '0600'
    path: /home/fcsqa/.ssh/another_vm_id_rsa
  - content: ${current_host_private_key}
    owner: root:root
    permissions: '0600'
    path: /home/fcsqa/.ssh/current_host_id_rsa

runcmd:
  - chown -R fcsqa:fcsqa /home/fcsqa/.ssh
