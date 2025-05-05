#cloud-config
groups:
  - docker
users:
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
  - nmap
runcmd:
%{ if AGENTLESS_SCAN == "false" }
  - curl ${agent_download_url} -o install.sh
  - sh install.sh
  - echo "Agent installed successfully."
%{ else }
  - echo "Agentless scan is enabled."
%{ endif }
  - curl "https://get.docker.com" -o install_docker.sh
  - sh install_docker.sh
  - docker pull debian:11
  - docker tag debian:11 debian:debian11
  - docker run -itd --name test_container debian:11
%{ for os, libraries in jsondecode(AGENLTESS_TEST_FILES) }
  - mkdir /opt/${os}/
  %{ for library in libraries }
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/${os}/${library} -o /opt/${os}/${library}
  - echo "Downloaded ${library} for ${os}"
  %{ endfor }
%{ endfor }
  - apt update
  - apt install -y openjdk-11-jdk
  - jar tf /opt/java/log4j-core-*.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j_test.java -o /opt/java/TestLog4j.java
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j-api-2.12.1.jar -o /opt/java/log4j-api-2.12.1.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j.xml -o /opt/java/log4j.xml
  - javac -cp /opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar /opt/java/TestLog4j.java
  - cd /opt/java
  - java -cp ".:/opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar" -Dlog4j2.configurationFile=/opt/java/log4j.xml TestLog4j
  - hostnamectl set-hostname ${hostname}
