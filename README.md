# Security Hub Historical Export

The CDK project will deploy all AWS resources and infrastructure required to automatically and continually export up to 100 million* Security Hub Findings in an AWS account as objects in a S3 bucket in JSON format.

If there are more than 100 million findings, you can reset the Step Function execution by following the steps listed [here](https://docs.aws.amazon.com/step-functions/latest/dg/tutorial-continue-new.html).

AWS Resources Include:
- (1) AWS Step Function
- (1) AWS SNS Topic for notifications on job status
- (1) AWS Systems Manager Parameter to track number of exported Security Hub findings
- (1) AWS Lambda Function & execution IAM role
- (1) AWS KMS key for creating S3 objects
- (1) Amazon S3 Bucket for storing Security Hub finding objects

Alternatively, you can deploy this solution using the CloudFormation template [security-hub-findings-historical-export](security-hub-findings-historical-export.yaml). You will need to download the lambda functions into a zip file and add the objects to a new or existing S3 bucket. Once added, you will need to pass the S3 bucket name and object keys (.zip files) in the CloudFormation parameters
- LambdaCodeSourceS3Bucket
- [ExportSecurityHubLambda](./security_hub_export_cdk/lambdas/load_sh_finding/get_sh_finding.py)

## Prerequisites

AWS Security Hub must be enabled in the AWS account.

## Build

To build this app, you need to be in the project root folder. Then run the following:

    $ npm install -g aws-cdk
    <installs AWS CDK>

    $ npm install
    <installs appropriate packages found in the package.json>

## Deploy

    $ cdk bootstrap aws://<INSERT_AWS_ACCOUNT>/<INSERT_REGION>
    <build S3 bucket to store files to perform deployment>

    $ cdk deploy SechubHistoricalPullStack
    <deploys the solution resources into the the AWS account>

## CDK Toolkit

The [`cdk.json`](./cdk.json) file in the root of this repository includes
instructions for the CDK toolkit on how to execute this program.

After building your TypeScript code, you will be able to run the CDK toolkits commands as usual:

    $ cdk ls
    <list all stacks in this program>

    $ cdk synth
    <generates and outputs cloudformation template>

    $ cdk deploy
    <deploys stack to your account>

    $ cdk diff
    <shows diff against deployed stack>

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

