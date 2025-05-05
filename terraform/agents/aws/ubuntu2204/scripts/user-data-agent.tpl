#cloud-config
groups:
  - docker
users:
  - default
  - name: fcsqa
    gecos: FCS QA
    primary_group: fcsqa
    groups: adm, wheel, docker
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${bastion_public_key}
      - ${test_user_public_key}
package_update: true
preserve_hostname: true
packages:
  - wget
  - nmap
  - liblog4j1.2-java
  - xmrig
runcmd:
  - curl "https://get.docker.com" -o install_docker.sh
  - sh install_docker.sh
  - docker pull ubuntu:22.04
  - docker tag ubuntu:22.04 ubuntu:ubuntu2204
  - docker run -itd --name test_container ubuntu:22.04
  - curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
  - dpkg -i session-manager-plugin.deb
%{ if AGENTLESS_SCAN == "false" }
  - curl ${agent_download_url} -o install.sh
  - sh install.sh
  - echo "Agent installed successfully."
%{ else }
  - echo "Agentless scan is enabled."
%{ endif }
  - sleep 30
  - snap install xmrig
  - snap refresh xmrig
  - curl "https://raw.githubusercontent.com/xmrig/xmrig/refs/heads/master/src/config.json" -o /root/.xmrig.json
  - chmod 600 /root/.xmrig.json
  - mkdir -p /root/snap/xmrig/20
  - cp /root/.xmrig.json /root/snap/xmrig/20/.xmrig.json
  - sleep 10
  - timeout 120s xmrig -c /root/.xmrig.json
%{ for os, libraries in jsondecode(AGENLTESS_TEST_FILES) }
  - mkdir /opt/${os}/
  %{ for library in libraries }
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/${os}/${library} -o /opt/${os}/${library}
  - echo "Downloaded ${library} for ${os}"
  %{ endfor }
%{ endfor }
  - apt install -y openjdk-8-jdk-headless
  - jar tf /opt/java/log4j-core-*.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j_test.java -o /opt/java/TestLog4j.java
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j-api-2.12.1.jar -o /opt/java/log4j-api-2.12.1.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j.xml -o /opt/java/log4j.xml
  - javac -cp /opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar /opt/java/TestLog4j.java
  - cd /opt/java
  - java -cp ".:/opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar" -Dlog4j2.configurationFile=/opt/java/log4j.xml TestLog4j
  - hostnamectl set-hostname ${hostname}
