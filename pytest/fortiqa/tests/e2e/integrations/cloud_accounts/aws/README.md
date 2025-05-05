## How to run tests
* Set up a `user_config.yaml` following instructions in https://github.com/lacework-dev/fortiqa/blob/main/README.md

* Run positive test cases ():

    `pytest cloud_accounts/test_aws_self_deployment.py`

* Run all test cases:

    `pytest --run-slow-self-deployment-tests cloud_accounts/test_aws_self_deployment.py`
