# VPC Reachability Analyzer Automated Assessment

    This SAM template provides a CloudFormation stack which deploys the infrastructure necessary for automated reachability assessment and notification using VPC Reachability Analyzer. Additionally, a sample Lambda function which detects security group changes, launches VPC Reachability Analyzer analyses, and notifies AWS administrators of any failed analyses is included.

### Services Used

- <a href="https://aws.amazon.com/iam/" target="_blank">AWS Identity and Access Management</a>
- <a href="https://aws.amazon.com/eventbridge/" target="_blank">Amazon EventBridge</a>
- <a href="https://aws.amazon.com/eventbridge/" target="_blank">Amazon Simple Notification Service</a>
- <a href="https://aws.amazon.com/vpc/" target="_blank">Amazon Virtual Private Cloud</a>
- <a href="https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html" target="_blank">VPC Reachability Analyzer</a>
- <a href="https://aws.amazon.com/cloudtrail/" target="_blank">AWS CloudTrail</a>
- <a href="https://aws.amazon.com/lambda/" target="_blank">AWS Lambda</a>

### Requirements for deployment

- <a href="https://aws.amazon.com/cli/" target="_blank">AWS CLI</a>
- <a href="https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html" target="_blank">AWS Serverless Application Model CLI v1.15.0+</a>

### Deploying

1. Clone this project to a local folder.
2. Change directory to inside the project folder.
3. Build the project using the SAM CLI in a terminal

```bash
sam build
```

4. Deploy the project using the SAM CLI in a terminal

```bash
sam deploy -g --capablities CAPABILITY_NAMED_IAM
```

#### Choose options

Options will be presented after executing the `sam deploy` command. Options are summarized below.

```bash
## The name of the CloudFormation stack
Stack Name [sam-app]:

## The region you want to deploy in
AWS Region [us-east-1]:

## The name of the SNS topic from which to send automated reachability assessment notifications
Parameter SnsTopicName []:

## The network block for the VPC which will be created by the template (i.e. 172.16.0.0/24)
Parameter VPCCidrBlock []:

## A subnet block residing within the VPCCidrBlock. (i.e. 172.16.0.0/26)
Confirm changes before deploy [y/N]:

## SAM needs permission to be able to create roles to connect to the resources in your template
Allow SAM CLI IAM role creation [Y/n]:

## Save your choice for later deployments
Save arguments to samconfig.toml [Y/n]:
```

SAM will then deploy the AWS CloudFormation stack to your AWS account. The ouputs provided by the CloudFormation template will be helpful while working through the blog post.

## Cleanup

1. Open the <a href="https://us-east-1.console.aws.amazon.com/cloudformation/home" target="_blank">CloudFormation console</a>
1. Locate a stack named _reachability-analyzer_
1. Select the radio option next to it
1. Select **Delete**
1. Select **Delete stack** to confirm

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
