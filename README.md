# aws-enum

AWS Enum is an AWS security auditing tool utilizing AWS's Python3 library, Boto3. 



<p align="center">
  <a href="https://example.com/">
    <img src="https://via.placeholder.com/72" alt="Logo" width=72 height=72>
  </a>

  <h3 align="center">Logo</h3>

  <p align="center">
    AWS Enum is an AWS account configuration auditing tool designed to scour all AWS services for security flaws and violations of best practices. AWS Enum is powered by AWS's Python3 SDK, Boto3. Currently, AWS Enum can audit 15 AWS services and runs over 40 test cases. To use AWS Enum you must have Boto3 installed and IAM progamatic permissions to generate credentials for the AWS CLI.
    <br>
    <a href="https://reponame/issues/new?template=bug.md">Report bug</a>
    ·
    <a href="https://reponame/issues/new?template=feature.md&labels=feature">Request feature</a>
  </p>
</p>


## Table of contents

- [About](#about)
- [Quick start](#quick-start)
- [Status](#status)
- [Contributing](#contributing)
- [Creators](#creators)
- [Thanks](#thanks)
- [Copyright and license](#copyright-and-license)


## About
AWS Enum is an AWS account configuration auditing tool designed to scour all AWS services for security flaws and violations of best practices. AWS Enum is powered by AWS's Python3 SDK, Boto3. Currently, AWS Enum can audit 15 AWS services and runs over 40 test cases. To use AWS Enum you must have Boto3 installed and IAM progamatic permissions to generate credentials for the AWS CLI. Currently AWS Enum will return a JSON blob with all of the findings for later processing. 

## Quick start

 1. Install boto3:
 pip3 install boto3
 
 2. Set AWS credentials.
 If not specified, boto3 will pull credentials locally from ~/.aws/credentials. Add your AWS credentials by typing `aws configure --profile $profile-name`
 
 
`
Both AWS keys are obtained by enabling progamatic access via AWS's IAM console.

## Status
As of 6/23/2020, this tool is in it's earliest form of development.

## Future Plans
Currently AWS Enum is configured to only return a findings report in JSON form then passed to my company's template -- generating an HTML report automatically. 

The future for AWS Enum will look like:

* More services and test cases
* CLI args to test multiple AWS account and regions
* CLI arg to return findings of a certain kind and service, i.e, only instances of disabled server-side encryption, or all findings from EC2.
* Visualization of AWS findings
* Automated AWS privilege escalation and horizontal pivoting
* Asset exfiltration (contingent on IAM permissions, exfiltrate sensitive data from common services like DynamoDB, S3, etc.) 
* AWS account map visualization, likely mindmaps similar to how [Bloodhound](https://github.com/BloodHoundAD/BloodHound) does it
* Automated SSRF exploitation and privilege escalation


## Creators

**P**


## Thanks

[]

## Copyright and license

Code and documentation copyright 2011-2018 the authors. Code released under the [MIT License](https://reponame/blob/master/LICENSE).

Enjoy :metal:
