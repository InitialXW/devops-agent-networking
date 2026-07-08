#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import * as dotenv from "dotenv";
import * as path from "path";
import { ProbeStack } from '../lib/probe-stack';
import { FlowLogsStack } from '../lib/flowlogs-stack';
import { McpStack } from '../lib/mcp-stack';
import { AgentStack } from '../lib/agent-stack';

dotenv.config({ path: path.resolve(__dirname, "../.env") });

const app = new cdk.App();

const env = {
  account: process.env.CDK_PROCESSING_ACCOUNT,
  region: process.env.CDK_PROCESSING_REGION,
};

const SSM_PREFIX = process.env.SSM_PREFIX || '/devops-agent-networking';

/*** Phase 1: Probe host + target + private DNS (the network landscape) ***/
const probeStack = new ProbeStack(app, 'NetDiagProbeStack', {
  stackName: 'NetDiagProbeStack',
  tags: { env: 'prod', ManagedBy: 'NetDiagProbeStack', 'auto-delete': 'no' },
  env,
});

/*** Phase 7: VPC Flow Logs + Athena query surface (flow_log_query tool backend) ***/
const flowLogsStack = new FlowLogsStack(app, 'NetDiagFlowLogsStack', {
  stackName: 'NetDiagFlowLogsStack',
  tags: { env: 'prod', ManagedBy: 'NetDiagFlowLogsStack', 'auto-delete': 'no' },
  env,
  vpc: probeStack.vpc,
});

/*** Phase 2: MCP server (API Gateway + tool-router Lambda over SSM) ***/
new McpStack(app, 'NetDiagMcpStack', {
  stackName: 'NetDiagMcpStack',
  tags: { env: 'prod', ManagedBy: 'NetDiagMcpStack', 'auto-delete': 'no' },
  env,
  probeInstanceId: probeStack.probeInstance.instanceId,
  ssmPrefix: SSM_PREFIX,
  flowLogsBucketName: flowLogsStack.flowLogsBucket.bucketName,
  athenaResultsBucketName: flowLogsStack.athenaResultsBucket.bucketName,
  glueDatabaseName: flowLogsStack.glueDatabaseName,
  glueTableName: flowLogsStack.glueTableName,
  athenaWorkgroupName: flowLogsStack.athenaWorkgroupName,
});

/*** Phase 3: Agent space + agent role + operator role + monitor association ***/
new AgentStack(app, 'NetDiagAgentStack', {
  stackName: 'NetDiagAgentStack',
  tags: { env: 'prod', ManagedBy: 'NetDiagAgentStack', 'auto-delete': 'no' },
  env,
});

// Phase 4: register the MCP server (Phase 2 endpoint) at account level with the API key
// (console/CLI step - the API-key secret cannot pass through CFN; see findings §6), then
// allow-list the 4 read-only network tools in this agent space.
