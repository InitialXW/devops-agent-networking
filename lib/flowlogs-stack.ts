import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as athena from 'aws-cdk-lib/aws-athena';
import { Construct } from 'constructs';

export interface FlowLogsStackProps extends cdk.StackProps {
  /** The network-landscape VPC (from ProbeStack) to attach flow logs to. */
  vpc: ec2.IVpc;
}

/**
 * Phase 7 (shared infra) - VPC Flow Logs + an Athena query surface.
 *
 * The agent troubleshoots historical/forensic traffic ("who is being REJECTed on
 * :5432, since when") via the flow_log_query MCP tool. That tool runs a FIXED,
 * partition-pruned, aggregation-only Athena query over the table defined here and
 * returns a compact structured verdict - never raw rows (Option M; see findings.md
 * s13.3). This stack owns everything the query needs:
 *
 *   1. an S3 bucket for the flow-log objects,
 *   2. a VPC flow log -> that bucket (CUSTOM format, plain text, non-Hive daily
 *      partitions - mirrors the customer's real config, findings.md s13.2),
 *   3. a Glue database + table over the bucket using PARTITION PROJECTION on `day`
 *      (MANDATORY at scale - without it every query full-scans the bucket, s13.5),
 *   4. an Athena results bucket, and
 *   5. an Athena WorkGroup with a bytes-scanned cutoff (hard cost backstop).
 *
 * The MCP tool-router Lambda (McpStack) is granted narrow read access to these and
 * gets their names via env vars.
 */
export class FlowLogsStack extends cdk.Stack {

  public readonly flowLogsBucket: s3.Bucket;
  public readonly athenaResultsBucket: s3.Bucket;
  public readonly glueDatabaseName: string;
  public readonly glueTableName: string;
  public readonly athenaWorkgroupName: string;

  constructor(scope: Construct, id: string, props: FlowLogsStackProps) {
    super(scope, id, props);

    const stackName = cdk.Stack.of(this).stackName;
    const account = this.account;
    const region = this.region;

    /*** S3 bucket for the VPC flow-log objects ***/
    // CDK owns the bucket delivery policy (createDefaultLoggingPolicy feature flag is
    // on in cdk.json), so it is cleaned up on destroy rather than orphaned.
    this.flowLogsBucket = new s3.Bucket(this, 'FlowLogsBucket', {
      bucketName: `netdiag-flow-logs-${cdk.Aws.ACCOUNT_ID}-${cdk.Aws.REGION}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      enforceSSL: true,
    });
    /******************************************************************************* */

    /*** VPC flow log -> S3 (CUSTOM format, plain text, non-Hive daily partitions) ***/
    // A single LogFormat.custom() string pins the exact field list AND order so the
    // Glue DDL below matches byte-for-byte. This mirrors the customer's CUSTOM format
    // (findings.md s13.2). File format defaults to plain-text and Hive partitions to
    // false, which is exactly the customer's setup - no destinationOptions needed.
    //
    // Demo tempo: 1-min aggregation so a seeded fault becomes queryable in minutes
    // (the customer runs 10-min; narrate that at demo time - findings.md s13.7).
    const FLOW_LOG_FIELDS = [
      '${version}', '${account-id}', '${interface-id}',
      '${srcaddr}', '${dstaddr}', '${srcport}', '${dstport}',
      '${protocol}', '${packets}', '${bytes}',
      '${start}', '${end}', '${action}', '${log-status}',
      '${vpc-id}', '${subnet-id}', '${flow-direction}',
    ].join(' ');

    new ec2.FlowLog(this, 'VpcFlowLog', {
      flowLogName: `${stackName}-VpcFlowLog`,
      resourceType: ec2.FlowLogResourceType.fromVpc(props.vpc),
      destination: ec2.FlowLogDestination.toS3(this.flowLogsBucket),
      trafficType: ec2.FlowLogTrafficType.ALL,
      maxAggregationInterval: ec2.FlowLogMaxAggregationInterval.ONE_MINUTE,
      logFormat: [ec2.LogFormat.custom(FLOW_LOG_FIELDS)],
    });
    /******************************************************************************* */

    /*** Athena query-results bucket (WorkGroup writes results here) ***/
    this.athenaResultsBucket = new s3.Bucket(this, 'AthenaResultsBucket', {
      bucketName: `netdiag-athena-results-${cdk.Aws.ACCOUNT_ID}-${cdk.Aws.REGION}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      enforceSSL: true,
      lifecycleRules: [{ expiration: cdk.Duration.days(7) }],
    });
    /******************************************************************************* */

    /*** Glue database + table with PARTITION PROJECTION on `day` ***/
    const glueDb = new glue.CfnDatabase(this, 'FlowLogsDatabase', {
      catalogId: account,
      databaseInput: {
        name: 'netdiag_flow_logs',
        description: 'VPC flow logs for DevOps Agent network diagnostics',
      },
    });
    this.glueDatabaseName = 'netdiag_flow_logs';
    this.glueTableName = 'vpc_flow_logs';

    // The flow log delivers to the non-Hive path
    //   s3://<bucket>/AWSLogs/<account>/vpcflowlogs/<region>/YYYY/MM/DD/...
    // Table LOCATION points at the region prefix; `day` is projected as the YYYY/MM/DD
    // segment. Single account/region here (the demo), so account+region are literal in
    // the template and only `day` is a partition key - keeps every query to one WHERE
    // clause on `day` and always partition-pruned.
    const logsLocation = `s3://${this.flowLogsBucket.bucketName}/AWSLogs/${account}/vpcflowlogs/${region}/`;

    const flowLogTable = new glue.CfnTable(this, 'FlowLogsTable', {
      catalogId: account,
      databaseName: this.glueDatabaseName,
      tableInput: {
        name: this.glueTableName,
        description: 'VPC flow logs (custom format), partition-projected by day',
        tableType: 'EXTERNAL_TABLE',
        partitionKeys: [{ name: 'day', type: 'string' }],
        parameters: {
          EXTERNAL: 'TRUE',
          'skip.header.line.count': '1',
          'projection.enabled': 'true',
          'projection.day.type': 'date',
          'projection.day.range': '2026/01/01,NOW',
          'projection.day.format': 'yyyy/MM/dd',
          'projection.day.interval': '1',
          'projection.day.interval.unit': 'DAYS',
          'storage.location.template': `${logsLocation}\${day}`,
        },
        storageDescriptor: {
          location: logsLocation,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
            parameters: { 'field.delim': ' ' },
          },
          // Column list + ORDER must match FLOW_LOG_FIELDS above exactly.
          columns: [
            { name: 'version', type: 'int' },
            { name: 'account_id', type: 'string' },
            { name: 'interface_id', type: 'string' },
            { name: 'srcaddr', type: 'string' },
            { name: 'dstaddr', type: 'string' },
            { name: 'srcport', type: 'int' },
            { name: 'dstport', type: 'int' },
            { name: 'protocol', type: 'bigint' },
            { name: 'packets', type: 'bigint' },
            { name: 'bytes', type: 'bigint' },
            { name: 'start', type: 'bigint' },
            { name: 'end', type: 'bigint' },
            { name: 'action', type: 'string' },
            { name: 'log_status', type: 'string' },
            { name: 'vpc_id', type: 'string' },
            { name: 'subnet_id', type: 'string' },
            { name: 'flow_direction', type: 'string' },
          ],
        },
      },
    });
    flowLogTable.addDependency(glueDb);
    /******************************************************************************* */

    /*** Athena WorkGroup - hard bytes-scanned cutoff is the cost backstop ***/
    const workgroup = new athena.CfnWorkGroup(this, 'FlowLogsWorkgroup', {
      name: `${stackName}-flowlogs`,
      description: 'Bounded WorkGroup for the flow_log_query MCP tool',
      recursiveDeleteOption: true,
      workGroupConfiguration: {
        enforceWorkGroupConfiguration: true,
        publishCloudWatchMetricsEnabled: false,
        // 1 GiB hard cap: partition-pruned aggregation queries scan far less; an
        // unbounded query fails here rather than running up cost.
        bytesScannedCutoffPerQuery: 1073741824,
        resultConfiguration: {
          outputLocation: `s3://${this.athenaResultsBucket.bucketName}/results/`,
        },
      },
    });
    this.athenaWorkgroupName = `${stackName}-flowlogs`;
    workgroup.node.addDependency(this.athenaResultsBucket);
    /******************************************************************************* */

    /*** Outputs ***/
    new cdk.CfnOutput(this, 'FlowLogsBucketName', { value: this.flowLogsBucket.bucketName });
    new cdk.CfnOutput(this, 'AthenaResultsBucketName', { value: this.athenaResultsBucket.bucketName });
    new cdk.CfnOutput(this, 'GlueDatabaseName', { value: this.glueDatabaseName });
    new cdk.CfnOutput(this, 'GlueTableName', { value: this.glueTableName });
    new cdk.CfnOutput(this, 'AthenaWorkgroupName', { value: this.athenaWorkgroupName });
    /******************************************************************************* */
  }
}
