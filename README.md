## How to run tests
You need to create a `user_config.yaml` following `config.yaml` format under pytest/fortiqa/tests/
### If using API V1 Client
1. Add **lw_api_key** and **lw_secret**
	If no existing API key and secret, go to **Settings->API Keys** to create a new one. You can access the generated secret by downloading the credential file.
2. Add **account_name**, it's the account name infront of **.lacework.net**. For example, if your testing environment is fortiqa.lacework.net, the account_name is <ins>fortiqa</ins>. And if your environment is sgmtest.qan.corp.lacework.net, the account name should be <ins>sgmtest.qan.corp</ins>
3. Add **user_email** and **user_email_password** Enter your exising <ins>Yahoo email </ins> and its 3rd App password. Remember, you need to add a user under **Settings->Users** using that Email address.
4. Add **sub_account**. A sub_account is the account you are using to test. It's may not be the same as the account_name in the Step 2. If there's no subaccount, please set `sub_account: ""`

**Note:**

The API Key/Secret pair in Step 1 **should belong** to the user in Step 3, and **should be inside** the sub_account in Step 4.


**The sequence for testing with API V1 starts from a new Email address**
1. Create 3rd App password
2. Log into the test environment with your own account, add the user with the new Email address
3. Log out from your account, and log into the testing environment using the new Email address. Check your inbox, and access the enviroment using the Login URL
4. Change to the sub_account(if any), and add API Key/ Secret
5. Download the created credential file to obtain the key and secret
6. Generate user_config.yaml using above data

### If using API V2 Client
You only need to provide **lw_api_key** and **lw_secret** using the same steps 2-5 above.

## How to contribute to the test repository
Please check [contribution guidelines for this project](CONTRIBUTING.md)
