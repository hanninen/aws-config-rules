# IAM_ROLE_ACCOUNT_TRUST_WHITELISTED Config Rule
This AWS Config Rule checks compliance for each IAM Role that trusts another AWS account and queries from the AWS System Manager's Parameter Store for a whitelist entry. This allows IAM role trust relationships to be whitelisted by a centralized security team and the Config Rules deployed to multiple accounts without configuring the whitelist rules in each rule separately.

## AWS Config role permissions
You need to add the following IAM policy for the IAM role used by the AWS Config, so that it has permission to assume the role in the security account and retrieve the whitelisted account values from the SSM Parameter Store.

Update the AWS Account ID `555555555555` and the IAM Role name `ROLE_NAME` with the correct values.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::555555555555:role/ROLE_NAME"
        }
    ]
}
```

## Security account IAM role
You need to create an IAM Role in the security account and add the trust relationship to your AWS account, where the IAM_ROLE_ACCOUNT_TRUST_WHITELISTED rule is running. Update the AWS Account ID `123456789012` to the correct value. 

### Trust relationship policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

The role also needs an IAM permission policy to be able to retrieve the values from the parameter store. Below is an example policy that allows the role to read the value. Update the following placeholder values with the correct ones:
* `REGION` with the correct region identifier (for example `us-east-1`)
* `555555555555` with the AWS account ID, where the parameter is created in.
* `/IAM/Roles/Whitelist/123456789012/ROLE_NAME` with the correct parameter key name

### Permission policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ssm:GetParameter",
            "Resource": "arn:aws:ssm:REGION:555555555555:parameter/IAM/Roles/Whitelist/123456789012/ROLE_NAME"
        }
    ]
}
```
## Deploying AWS Config Rule parameter
Update the `parameter.json` file with the security account's IAM Role ARN for the `SSM_ROLE_ARN` parameter and then follow the deployment instructions from the top-level README.