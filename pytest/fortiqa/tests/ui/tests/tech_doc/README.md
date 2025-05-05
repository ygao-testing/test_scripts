test_documentation_links.py

Description:
Testcase navigates the different Lacework urls provided in the testcase, retrieves and verifies the documentation links.
Running the testcase verifies the following requirement.
a. Fortinet documentation links are valid
b. There are no Lacework instances in the documentation links

Dependencies:
ui/lib/utils/lacework_webcrawl.py  (Utility library for navigating urls and retrieving documentation links)
ui/data/base_xpaths.py  (Definition file containing Lacework website xpaths)


Example command line:
>  pytest test_documentation_links.py


Example config.yaml:
app:
  customer:
    user_email: "fortiqa@yahoo.com"
    user_email_password: "password"
ui:
  url: "https://fortiqa.lacework.net"
