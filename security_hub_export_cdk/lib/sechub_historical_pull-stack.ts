import { Stack, StackProps, Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { Key } from 'aws-cdk-lib/aws-kms';
import { BlockPublicAccess, Bucket, BucketEncryption, ObjectOwnership, StorageClass } from 'aws-cdk-lib/aws-s3';
import { Function, Runtime, Code } from 'aws-cdk-lib/aws-lambda';
import { join } from 'path';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Choice, Condition, Fail, StateMachine, Succeed, TaskStateBase } from 'aws-cdk-lib/aws-stepfunctions';
import { LambdaInvoke } from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { Rule } from 'aws-cdk-lib/aws-events';
import * as target from 'aws-cdk-lib/aws-events-targets';
import { Topic } from 'aws-cdk-lib/aws-sns';


export class SechubHistoricalPullStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // KMS Key for S3 Bucket for Security Hub Export
    const s3_kms_key = new Key(this, 's3_kms_key', {
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description: 'KMS key for security hub findings in S3 bucket.',
      enableKeyRotation: false,
      alias: 'sechub_export_key'
    });

    // S3 Bucket for Security Hub Export
    const security_hub_export_bucket = new Bucket(this, 'security_hub_export_bucket', {
      removalPolicy: RemovalPolicy.RETAIN,
      bucketKeyEnabled: true,
      encryption: BucketEncryption.KMS,
      encryptionKey: s3_kms_key,
      enforceSSL: true,
      versioned: true,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
      publicReadAccess: false,
      lifecycleRules: [{
        expiration: Duration.days(365),
        transitions: [{
            storageClass: StorageClass.GLACIER,
            transitionAfter: Duration.days(31)
        }]
    }]
    });
  
    // Custom Security Hub Lambda Function Resources 
    const get_sec_hub_findings_role = new iam.Role(this, 'get_sec_hub_findings_role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "SHFindingReadAutomationRole",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaSHLogReadExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });

    const sechub_count_parameter = new StringParameter(this, 'sechub_count_parameter', {
      description: 'The Count for Security Hub findings.',
      parameterName: '/sechubexport/count',
      stringValue: '0'
    });

    const get_sec_hub_findings_function = new Function(this, 'get_sec_hub_findings_function', {
      runtime: Runtime.PYTHON_3_8,
      code: Code.fromAsset(join(__dirname, "../lambdas/load_sh_finding")),
      handler: 'get_sh_finding.lambda_handler',
      description: 'Get all AWS Security Hub findings.',
      timeout: Duration.seconds(900),
      memorySize: 1024,
      role: get_sec_hub_findings_role,
      reservedConcurrentExecutions: 100,
      environment:{
        REGION: this.region,
        S3_BUCKET: security_hub_export_bucket.bucketName,
        KMS_KEY_ID: s3_kms_key.keyArn,
        SSM_PARAMETER_COUNT: sechub_count_parameter.parameterName
      },
    });

    const get_sec_hub_finding_policy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "GetSHFinding",
          effect: iam.Effect.ALLOW,
          actions: [
            "securityhub:Get*"
          ],
          resources: [
            '*'
          ]   
        }),
        new iam.PolicyStatement({
          sid: "KMSDecrypt",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:Describe*",
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ],
          resources: [
            s3_kms_key.keyArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SSMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ssm:GetParameter",
            "ssm:PutParameter"
          ],
          resources: [
            sechub_count_parameter.parameterArn,
          ]   
        }),
        new iam.PolicyStatement({
          sid: "EC2Allow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ec2:CreateNetworkInterface",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DeleteNetworkInterface"
          ],
          resources: [
            "*",
          ]   
        }),
      ],
    });

    new iam.ManagedPolicy(this, 'lambdaGetSHFindingManagedPolicy', {
      description: 'Get Security Hub Findings',
      document:get_sec_hub_finding_policy,
      managedPolicyName: 'lambdaGetSHFindingManagedPolicy',
      roles: [get_sec_hub_findings_role]
    });

    security_hub_export_bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        's3:GetObject*',
        's3:ListBucket',
        's3:PutObject*'
      ],
      resources: [
        security_hub_export_bucket.bucketArn,
        security_hub_export_bucket.arnForObjects('*')
      ],
      principals: [
        new iam.ArnPrincipal(get_sec_hub_findings_role.roleArn)],
    }));

    // Step Function State Machine for orchestrating Security Hub export lambda
    const get_sec_hub_finding_task = new LambdaInvoke(this, "GetSecurityHubFindings", {
      lambdaFunction: get_sec_hub_findings_function,
      inputPath: '$',
      outputPath: '$',
    })

    get_sec_hub_finding_task.addRetry({
      errors:['States.ALL'],
      maxAttempts: 5,
      backoffRate: 2,
      interval: Duration.seconds(10),
    })

    const jobFailed = new Fail(this, 'Job Failed', {
      cause: 'Security Hub Export Failed.',
      error: '$',
    });

    const definition = 
    get_sec_hub_finding_task
    .next(new Choice(this, 'Check for NextToken in Security Hub Findings response.')
    .when(Condition.isNotNull('$.Payload.NextToken'), get_sec_hub_finding_task)
    .otherwise(new Succeed(this, "Security Hub Export Succeded"))
    )

    const sechub_state_machine = new StateMachine(this, "sechub_state_machine", {
      definition,
      stateMachineName: 'sec_hub_finding_export'
    });

    sechub_count_parameter.grantWrite(sechub_state_machine)

    // SNS Topic
    const sec_hub_status_topic = new Topic(this, 'sec_hub_status_topic', {
      displayName: 'SNS Topic for Security Hub Export Status.',
      topicName: 'Security_Hub_Export_Status'
    });

    // CloudWatch EventBridge rule for Step Function status change
    const step_function_status_change = new Rule(this, 'step_function_status_change', {
      description: 'Alerts when state machine status changes for Security Hub export.',
      enabled: true,
      eventPattern: {
        "source": [
          "aws.states"
        ],
        "detailType": ["Step Functions Execution Status Change"],
        "detail": {
          "status": [
            "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"
          ],
          "executionArn": [
            sechub_state_machine.stateMachineArn
          ]
        }
      },
      ruleName: 'Alert_Sec_Hub_Export_Status_Change',
      targets: [new target.SnsTopic(sec_hub_status_topic)]
    }
    );
    
  }
}
