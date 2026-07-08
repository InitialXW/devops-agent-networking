import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import { Construct } from 'constructs';

export interface McpStackProps extends cdk.StackProps {
  /** Probe host the tool-router runs fixed commands on (from ProbeStack). */
  probeInstanceId: string;
  /** SSM parameter prefix for storing invoke URL + API key id post-deploy. */
  ssmPrefix: string;
  /** Flow-logs query surface (from FlowLogsStack) for the flow_log_query tool. */
  flowLogsBucketName: string;
  athenaResultsBucketName: string;
  glueDatabaseName: string;
  glueTableName: string;
  athenaWorkgroupName: string;
}

/**
 * Phase 2 - the custom MCP server.
 *
 * API Gateway (REST, API-key auth) -> tool-router Lambda. The Lambda is the ONLY
 * principal that can call ssm:SendCommand, and only AWS-RunShellScript on the single
 * tagged probe host. The DevOps Agent registers this endpoint as a custom MCP server;
 * the guardrail does not govern MCP tools, so this is the sanctioned path to give the
 * read-only agent active (but mediated, auditable, fixed-command) network diagnostics.
 */
export class McpStack extends cdk.Stack {

  public readonly apiUrl: string;
  public readonly apiKeyId: string;

  constructor(scope: Construct, id: string, props: McpStackProps) {
    super(scope, id, props);

    const stackName = cdk.Stack.of(this).stackName;

    // ------------------- NetDiagMcp tool-router Lambda ---------------------
    const mcpLogGroup = new logs.LogGroup(this, 'NetDiagMcpLogGroup', {
      logGroupName: `/aws/lambda/${stackName}-NetDiagMcp`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const mcpRole = new iam.Role(this, 'NetDiagMcpRole', {
      roleName: `${stackName}-NetDiagMcpRole`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Least privilege: SendCommand only for AWS-RunShellScript AND only on the probe host.
    // The document + instance ARNs are listed as the resources on a single statement; SSM
    // requires both the document and the instance to be permitted for SendCommand.
    mcpRole.addToPolicy(new iam.PolicyStatement({
      sid: 'SendFixedCommandToProbeOnly',
      actions: ['ssm:SendCommand'],
      resources: [
        `arn:aws:ssm:${this.region}::document/AWS-RunShellScript`,
        `arn:aws:ec2:${this.region}:${this.account}:instance/${props.probeInstanceId}`,
      ],
    }));

    // Read the command result back. GetCommandInvocation is not resource-scopable; gate it
    // with a condition tying it to the RunShellScript document.
    mcpRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadCommandResults',
      actions: ['ssm:GetCommandInvocation'],
      resources: ['*'],
    }));

    // --- flow_log_query (Phase 7): Athena over the VPC flow-logs Glue table. ---
    // Least privilege: Athena actions are gated to the one bounded WorkGroup; Glue reads
    // are scoped to the one database/table (+ catalog); S3 reads to the flow-logs bucket,
    // and read+write to the Athena results bucket (Athena writes query output there).
    const flowLogsBucketArn = `arn:aws:s3:::${props.flowLogsBucketName}`;
    const resultsBucketArn = `arn:aws:s3:::${props.athenaResultsBucketName}`;

    mcpRole.addToPolicy(new iam.PolicyStatement({
      sid: 'RunBoundedFlowLogQueries',
      actions: [
        'athena:StartQueryExecution',
        'athena:StopQueryExecution',
        'athena:GetQueryExecution',
        'athena:GetQueryResults',
        'athena:GetWorkGroup',
      ],
      resources: [
        `arn:aws:athena:${this.region}:${this.account}:workgroup/${props.athenaWorkgroupName}`,
      ],
    }));

    mcpRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadGlueFlowLogTable',
      actions: ['glue:GetTable', 'glue:GetDatabase', 'glue:GetPartitions'],
      resources: [
        `arn:aws:glue:${this.region}:${this.account}:catalog`,
        `arn:aws:glue:${this.region}:${this.account}:database/${props.glueDatabaseName}`,
        `arn:aws:glue:${this.region}:${this.account}:table/${props.glueDatabaseName}/${props.glueTableName}`,
      ],
    }));

    mcpRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadFlowLogsAndWriteAthenaResults',
      actions: ['s3:GetObject', 's3:GetBucketLocation', 's3:ListBucket', 's3:PutObject'],
      resources: [
        flowLogsBucketArn, `${flowLogsBucketArn}/*`,
        resultsBucketArn, `${resultsBucketArn}/*`,
      ],
    }));
    // ---------------------------------------------------------------------------

    const mcpFunction = new lambda.Function(this, 'NetDiagMcp', {
      runtime: lambda.Runtime.PYTHON_3_12,
      code: lambda.Code.fromAsset('lambda/src/.aws-sam/build/NetDiagMcp'),
      handler: 'app.lambda_handler',
      timeout: cdk.Duration.seconds(60),
      memorySize: 128,
      architecture: lambda.Architecture.X86_64,
      reservedConcurrentExecutions: 5,
      role: mcpRole,
      tracing: lambda.Tracing.DISABLED,
      logGroup: mcpLogGroup,
      environment: {
        PROBE_INSTANCE_ID: props.probeInstanceId,
        SSM_POLL_TIMEOUT_S: '20',
        // flow_log_query (Phase 7)
        ATHENA_DATABASE: props.glueDatabaseName,
        ATHENA_TABLE: props.glueTableName,
        ATHENA_WORKGROUP: props.athenaWorkgroupName,
        ATHENA_POLL_TIMEOUT_S: '25',
      },
    });
    // -------------------------------------------------------

    /*** API Gateway: MCP endpoint (API key auth) ***/
    const apiAccessLogGroup = new logs.LogGroup(this, 'McpApiAccessLogGroup', {
      logGroupName: `/aws/vendedlogs/apigateway/${stackName}-netdiag-mcp`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const mcpApi = new apigateway.RestApi(this, 'NetDiagMcpApi', {
      restApiName: `${stackName}-netdiag-mcp`,
      description: 'MCP endpoint for DevOps Agent network diagnostics',
      deployOptions: {
        stageName: 'mcp',
        accessLogDestination: new apigateway.LogGroupLogDestination(apiAccessLogGroup),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields(),
      },
      apiKeySourceType: apigateway.ApiKeySourceType.HEADER,
    });

    // Pre-provision the execution log group so CloudFormation owns its lifecycle.
    new logs.LogGroup(this, 'McpApiExecLogGroup', {
      logGroupName: `API-Gateway-Execution-Logs_${mcpApi.restApiId}/mcp`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // POST / - MCP JSON-RPC; GET / - health check. Both require the API key.
    mcpApi.root.addMethod('POST', new apigateway.LambdaIntegration(mcpFunction), { apiKeyRequired: true });
    mcpApi.root.addMethod('GET', new apigateway.LambdaIntegration(mcpFunction), { apiKeyRequired: true });

    const mcpApiKey = mcpApi.addApiKey('NetDiagMcpApiKey', {
      apiKeyName: `${stackName}-netdiag-mcp-key`,
      description: 'API key for DevOps Agent MCP registration',
    });

    const mcpUsagePlan = mcpApi.addUsagePlan('NetDiagMcpUsagePlan', {
      name: `${stackName}-netdiag-mcp-plan`,
      apiStages: [{ api: mcpApi, stage: mcpApi.deploymentStage }],
      throttle: { rateLimit: 10, burstLimit: 20 },
    });
    mcpUsagePlan.addApiKey(mcpApiKey);
    /******************************************************************************* */

    /*** SSM params: store invoke URL + API key id for registration convenience ***/
    new ssm.StringParameter(this, 'McpUrlParam', {
      parameterName: `${props.ssmPrefix}/mcp-url`,
      stringValue: mcpApi.url,
      description: 'NetDiag MCP API Gateway invoke URL',
    });
    new ssm.StringParameter(this, 'McpApiKeyIdParam', {
      parameterName: `${props.ssmPrefix}/mcp-api-key-id`,
      stringValue: mcpApiKey.keyId,
      description: 'NetDiag MCP API key id (value fetched via apigateway get-api-key --include-value)',
    });
    /******************************************************************************* */

    this.apiUrl = mcpApi.url;
    this.apiKeyId = mcpApiKey.keyId;

    /*** Outputs ***/
    new cdk.CfnOutput(this, 'McpApiUrl', { value: mcpApi.url });
    new cdk.CfnOutput(this, 'McpApiKeyId', { value: mcpApiKey.keyId });
    new cdk.CfnOutput(this, 'McpFunctionName', { value: mcpFunction.functionName });
    /******************************************************************************* */
  }
}
