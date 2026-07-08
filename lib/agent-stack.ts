import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as devopsagent from 'aws-cdk-lib/aws-devopsagent';
import { Construct } from 'constructs';

export interface AgentProps extends cdk.StackProps {}

/**
 * Phase 3 - the DevOps Agent space that investigates the network landscape.
 *
 * Minimal POC (no Slack/SQS/lifecycle): an Agent Space + agent role (assumed by the
 * service to monitor this account, read-only via AIDevOpsAgentAccessPolicy) + operator
 * app role (web console access) + a monitor association.
 *
 * The agent's own role deliberately has NO ssm:SendCommand (the guardrail blocks it
 * anyway, findings s1) and an explicit Deny on ssm:List* so it cannot read the probe
 * command history out of SSM - active network diagnostics reach the agent ONLY through
 * the registered custom MCP server (Phase 2/4), keeping the execution path auditable.
 */
export class AgentStack extends cdk.Stack {

  public readonly agentSpaceId: string;

  constructor(scope: Construct, id: string, props: AgentProps) {
    super(scope, id, props);

    const stackName = cdk.Stack.of(this).stackName;

    /*** IAM Role: Agent Space Role (assumed by the DevOps Agent service) ***/
    const agentRole = new iam.Role(this, 'DevOpsAgentRole', {
      roleName: `${stackName}-AgentRole`,
      assumedBy: new iam.ServicePrincipal('aidevops.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
          ArnLike: {
            'aws:SourceArn': `arn:aws:aidevops:${this.region}:${this.account}:agentspace/*`,
          },
        },
      }),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AIDevOpsAgentAccessPolicy'),
      ],
    });

    // Inline: allow creating the Resource Explorer SLR the agent uses for discovery.
    agentRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowCreateServiceLinkedRoles',
      actions: ['iam:CreateServiceLinkedRole'],
      resources: [
        `arn:aws:iam::${this.account}:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer`,
      ],
      conditions: { StringEquals: { 'iam:AWSServiceName': 'resource-explorer-2.amazonaws.com' } },
    }));

    // Explicit Deny: AIDevOpsAgentAccessPolicy grants ssm:List* (incl. ListCommands /
    // ListCommandInvocations = the probe shell-command content). The agent must learn
    // network state via the MCP tools' STRUCTURED output, not by reading raw SSM history.
    agentRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      actions: ['ssm:List*'],
      resources: ['*'],
    }));
    /******************************************************************************* */

    /*** IAM Role: Operator App Role (web console access) ***/
    const operatorRole = new iam.Role(this, 'DevOpsOperatorRole', {
      roleName: `${stackName}-OperatorRole`,
      assumedBy: new iam.ServicePrincipal('aidevops.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
          ArnLike: {
            'aws:SourceArn': `arn:aws:aidevops:${this.region}:${this.account}:agentspace/*`,
          },
        },
      }),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AIDevOpsOperatorAppAccessPolicy'),
      ],
    });

    // GA grants sts:TagSession in addition to sts:AssumeRole on the operator trust.
    (operatorRole.node.defaultChild as iam.CfnRole).addPropertyOverride(
      'AssumeRolePolicyDocument.Statement.0.Action',
      ['sts:AssumeRole', 'sts:TagSession'],
    );

    // Supplement: override AIDevOpsOperatorAppAccessPolicy's ABAC resource scope
    // (it scopes actions to agentspace/${aws:PrincipalTag/AgentSpaceId}; we don't set
    // that tag, so the condition never matches). resources:'*' unblocks operator reads.
    operatorRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        'aidevops:GetAgentSpace',
        'aidevops:GetAssociation',
        'aidevops:ListAssociations',
        'aidevops:ListBacklogTasks',
        'aidevops:GetBacklogTask',
        'aidevops:CreateBacklogTask',
        'aidevops:UpdateBacklogTask',
        'aidevops:ListKnowledgeItems',
        'aidevops:GetKnowledgeItem',
        'aidevops:CreateKnowledgeItem',
        'aidevops:UpdateKnowledgeItem',
        'aidevops:DeleteKnowledgeItem',
        'aidevops:ListKnowledgeItemVersions',
        'aidevops:ListChats',
        'aidevops:CreateChat',
        'aidevops:SendMessage',
        'aidevops:ListPendingMessages',
        'aidevops:ListExecutions',
        'aidevops:ListJournalRecords',
        'aidevops:ListGoals',
        'aidevops:UpdateGoal',
        'aidevops:ListRecommendations',
        'aidevops:GetRecommendation',
        'aidevops:UpdateRecommendation',
        'aidevops:DescribeSupportLevel',
        'aidevops:EndChatForCase',
        'aidevops:InitiateChatForCase',
        'aidevops:DiscoverTopology',
        'aidevops:GetService',
        'aidevops:ListServices',
        'aidevops:ListWebhooks',
        'aidevops:ListAgentSpaces',
        'aidevops:GetOperatorApp',
        'aidevops:ListTagsForResource',
        'aidevops:SearchServiceAccessibleResource',
      ],
      resources: ['*'],
    }));
    /******************************************************************************* */

    /*** Agent Space ***/
    const agentSpace = new devopsagent.CfnAgentSpace(this, 'AgentSpace', {
      name: 'devops-agent-networking',
      description: 'Network diagnostics space - investigates VPC reachability/DNS/routing faults using a custom MCP server that runs dig/nc/ping/traceroute on an EC2 probe via SSM',
      operatorApp: {
        iam: { operatorAppRoleArn: operatorRole.roleArn },
      },
    });
    /******************************************************************************* */

    /*** Monitor Association (this account, read-only) ***/
    const monitorAssociation = new devopsagent.CfnAssociation(this, 'MonitorAssociation', {
      agentSpaceId: agentSpace.attrAgentSpaceId,
      serviceId: 'aws',
      configuration: {
        aws: {
          accountId: this.account,
          accountType: 'monitor',
          assumableRoleArn: agentRole.roleArn,
        },
      },
    });
    monitorAssociation.addDependency(agentSpace);
    /******************************************************************************* */

    /*** Outputs ***/
    this.agentSpaceId = agentSpace.attrAgentSpaceId;
    new cdk.CfnOutput(this, 'AgentSpaceId', { value: agentSpace.attrAgentSpaceId });
    new cdk.CfnOutput(this, 'AgentSpaceArn', { value: agentSpace.attrArn });
    new cdk.CfnOutput(this, 'AgentRoleArn', { value: agentRole.roleArn });
    new cdk.CfnOutput(this, 'OperatorRoleArn', { value: operatorRole.roleArn });
    /******************************************************************************* */
  }
}
