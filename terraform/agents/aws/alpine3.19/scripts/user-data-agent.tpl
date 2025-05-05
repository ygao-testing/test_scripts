#cloud-config
groups:
    - docker
users:
    - name: fcsqa
      primary_group: fcsqa
      groups: adm, wheel, docker
      doas:
        - permit fcsqa as root
      ssh_authorized_keys:
        - ${test_user_public_key}
packages:
    - curl
    - openssh-server-pam
    - doas
    - docker
package_update: true
preserve_hostname: true
runcmd:
    - sed -i "s/#UsePAM no/UsePAM yes/" /etc/ssh/sshd_config
    - rc-service sshd restart
    - sleep 30
    - rc-update add cgroups
    - rc-update add docker default
    - sleep 30
    - rc-service cgroups start
    - rc-service docker start
    - sleep 10
    - docker pull alpine:3.19
    - docker tag alpine:3.19 alpine:alpine3.19
    - docker run -itd --name test_container alpine:3.19
%{ if AGENTLESS_SCAN == "false" }
    - curl ${agent_download_url} -o install.sh
    - sh install.sh
    - echo "Agent installed successfully."
%{ else }
    - echo "Agentless scan is enabled."
%{ endif }
%{ for os, libraries in jsondecode(AGENLTESS_TEST_FILES) }
  - mkdir /opt/${os}/
  %{ for library in libraries }
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/${os}/${library} -o /opt/${os}/${library}
  - echo "Downloaded ${library} for ${os}"
  %{ endfor }
%{ endfor }
  - apk update
  - apk add openjdk8-jre-headless
  - jar tf /opt/java/log4j-core-*.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j_test.java -o /opt/java/TestLog4j.java
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j-api-2.12.1.jar -o /opt/java/log4j-api-2.12.1.jar
  - curl https://fortiqa-public-test-files.s3.us-east-1.amazonaws.com/java/log4j.xml -o /opt/java/log4j.xml
  - javac -cp /opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar /opt/java/TestLog4j.java
  - cd /opt/java
  - java -cp ".:/opt/java/log4j-core-2.12.1.jar:/opt/java/log4j-api-2.12.1.jar" -Dlog4j2.configurationFile=/opt/java/log4j.xml TestLog4j
  - hostname ${hostname}
