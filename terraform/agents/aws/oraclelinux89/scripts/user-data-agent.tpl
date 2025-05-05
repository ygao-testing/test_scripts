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
  - yum-utils
runcmd:
%{ if AGENTLESS_SCAN == "false" }
  - wget ${agent_download_url}
  - bash install.sh
  - echo "Agent installed successfully."
%{ else }
  - echo "Agentless scan is enabled."
%{ endif }
  - yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  - yum install -y docker-ce docker-ce-cli containerd.io
  - systemctl enable docker
  - systemctl start docker
  - sleep 10
  - docker pull oraclelinux:8
  - docker tag oraclelinux:8 oraclelinux:oraclelinux89
  - docker run -dit --name test_container docker.io/library/oraclelinux:8
%{ for os, libraries in jsondecode(AGENLTESS_TEST_FILES) }
  - mkdir /opt/${os}/
  %{ for library in libraries }
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/${os}/${library} -o /opt/${os}/${library}
  - echo "Downloaded ${library} for ${os}"
  %{ endfor }
%{ endfor }
  - yum install -y java-1.8.0-openjdk-devel
  - jar tf /opt/java/log4j-core-*.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j_test.java -o /opt/java/TestLog4j.java
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j-api-2.12.1.jar -o /opt/java/log4j-api-2.12.1.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j.xml -o /opt/java/log4j.xml
  - javac -cp /opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar /opt/java/TestLog4j.java
  - cd /opt/java
  - java -cp ".:/opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar" -Dlog4j2.configurationFile=/opt/java/log4j.xml TestLog4j
  - hostnamectl set-hostname ${hostname}
