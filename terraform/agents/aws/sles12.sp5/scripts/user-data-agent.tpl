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
  - wget
  - nmap
  - docker
runcmd:
  - systemctl start docker
  - systemctl enable docker
  - sleep 5
  - docker pull registry.suse.com/suse/sles12sp5
  - docker tag registry.suse.com/suse/sles12sp5:latest registry.suse.com/suse/sles12sp5:sles12.sp5
  - docker run -dit --name test_container registry.suse.com/suse/sles12sp5
%{ if AGENTLESS_SCAN == "false" }
  - wget ${agent_download_url}
  - bash install.sh
  - echo "Agent installed successfully."
%{ else }
  - echo "Agentless scan is enabled."
%{ endif }
%{ for os, libraries in jsondecode(AGENLTESS_TEST_FILES) }
  - mkdir /opt/${os}/
  %{ for library in libraries }
  - wget https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/${os}/${library} -O /opt/${os}/${library}
  - echo "Downloaded ${library} for ${os}"
  %{ endfor }
%{ endfor }
  - zypper install -y java-1_8_0-openjdk-devel
  - jar tf /opt/java/log4j-core-*.jar
  - wget https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j_test.java -O /opt/java/TestLog4j.java
  - wget https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j-api-2.12.1.jar -O /opt/java/log4j-api-2.12.1.jar
  - wget https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j.xml -O /opt/java/log4j.xml
  - javac -cp /opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar /opt/java/TestLog4j.java
  - cd /opt/java
  - java -cp ".:/opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar" -Dlog4j2.configurationFile=/opt/java/log4j.xml TestLog4j
  - hostnamectl set-hostname ${hostname}
