from typing import Any

packages: dict[str, Any] = {
  "java": [
    {
      "filename": "commons-compress-1.21.jar",
      "package_name": "org.apache.commons:commons-compress",
      "vulnerabilities": [
        "CVE-2024-25710"
      ]
    },
    {
      "filename": "guava-31.1-jre.jar",
      "package_name": "com.google.guava:guava",
      "vulnerabilities": [
        "CVE-2020-8908",
        "CVE-2023-2976"
      ]
    },
    {
      "filename": "jackson-databind-2.9.6.jar",
      "package_name": "com.fasterxml.jackson.core:jackson-databind",
      "vulnerabilities": [
        "CVE-2018-14718",
        "CVE-2019-12086",
        "CVE-2019-12384"
      ]
    },
    {
      "filename": "log4j-core-2.12.1.jar",
      "package_name": "org.apache.logging.log4j:log4j-core",
      "vulnerabilities": [
        "CVE-2021-44228",
        "CVE-2021-44832",
        "CVE-2021-45105"
      ]
    }
  ]
}
