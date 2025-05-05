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
  - docker
runcmd:
  - sudo dnf install -y https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm
  - |
    #!/bin/bash
    echo "AGENTLESS_SCAN is: '${AGENTLESS_SCAN}', length: $(echo -n ${AGENTLESS_SCAN} | wc -c)"
    if [ "$(echo ${AGENTLESS_SCAN} | xargs)" = "true" ]; then
      echo "Agentless scan is enabled."
    else
      curl ${agent_download_url} -o "install.sh"
      bash install.sh
      echo "Agent installed successfully."
    fi
  - systemctl enable docker
  - systemctl start docker
  - sleep 10
  - docker pull amazonlinux:2023
  - docker tag amazonlinux:2023 amazonlinux:amazonlinux2023
  - docker run -dit --name test_container public.ecr.aws/amazonlinux/amazonlinux:2023
%{ for os, libraries in jsondecode(AGENLTESS_TEST_FILES) }
  - mkdir /opt/${os}/
  %{ for library in libraries }
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/${os}/${library} -o /opt/${os}/${library}
  - echo "Downloaded ${library} for ${os}"
  %{ endfor }
%{ endfor }
  - yum install -y java-21-amazon-corretto-devel
  - jar tf /opt/java/log4j-core-*.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j_test.java -o /opt/java/TestLog4j.java
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j-api-2.12.1.jar -o /opt/java/log4j-api-2.12.1.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j.xml -o /opt/java/log4j.xml
  - javac -cp /opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar /opt/java/TestLog4j.java
  - cd /opt/java
  - java -cp ".:/opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar" -Dlog4j2.configurationFile=/opt/java/log4j.xml TestLog4j
  - hostnamectl set-hostname ${hostname}
