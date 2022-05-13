# Security Hub Historical Export

The CDK project in the security_hub_export_cdk folder will deploy a solution to automatically and continually export up to 100 million* Security Hub Findings in an AWS account as objects in a S3 bucket in JSON format.

If there are more than 100 million findings, you can reset the Step Function execution by following the steps listed [here](https://docs.aws.amazon.com/step-functions/latest/dg/tutorial-continue-new.html).

## Build

To build this app, you need to be in the project root folder. Then run the following:

npm install -g aws-cdk
npm install
npm run build

    $ npm install -g aws-cdk
    <installs AWS CDK>

    $ npm install
    <installs appropriate packages>

    $ npm run build
    <build TypeScript files>

## Deploy

    $ cdk bootstrap aws://<INSERT_AWS_ACCOUNT>/<INSERT_REGION>
    <build S3 bucket to store files to perform deployment>

    $ cdk deploy
    <deploys the cdk project into the authenticated AWS account>

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

