#cloud-config
users:
  - default
  - name: fcsqa
    groups: adm, wheel
    ssh_authorized_keys:
      - ${test_user_public_key}

write_files:
  - content: ${private_key}
    owner: fcsqa:fcsqa
    permissions: '0600'
    path: /home/fcsqa/.ssh/id_rsa

runcmd:
  - chown -R fcsqa:fcsqa /home/fcsqa/.ssh
