import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as route53 from 'aws-cdk-lib/aws-route53';
import { Construct } from 'constructs';

export interface ProbeStackProps extends cdk.StackProps {}

/**
 * Phase 1 — the "complex network landscape" the DevOps Agent troubleshoots.
 *
 * A single VPC with:
 *   - a PROBE host (public subnet) that holds the network diagnostic tools
 *     (dig/nc/ping/traceroute/...). The MCP tool-router Lambda runs FIXED commands
 *     on THIS host via SSM. It is the agent's vantage point into the network.
 *   - a TARGET host (public subnet) running nginx on ports 80 AND 5432. Whether the
 *     probe can reach those ports is governed PURELY by the target's security group,
 *     so faults are genuine (real packets, real timeouts) and toggleable for the demo.
 *   - a Route53 PRIVATE hosted zone (corp.internal) so `db.corp.internal` resolves only
 *     inside the VPC — a split-horizon DNS story the agent can observe via resolve_dns.
 *
 * Baseline is HEALTHY (SG allows 80 + 5432 + ICMP from the probe). Phase 5 `seed.sh`
 * removes the 5432 ingress rule to inject the fault; `reset.sh` restores it.
 *
 * No NAT gateway: both hosts sit in public subnets with public IPs so the SSM agent
 * reaches the SSM endpoints and user-data can install packages over the IGW. Network
 * SEGMENTATION (and the demo fault) is enforced by security groups, not subnet routing.
 */
export class ProbeStack extends cdk.Stack {

  /*** The network landscape VPC (flow logs attach to this in FlowLogsStack) ***/
  public readonly vpc: ec2.Vpc;
  /******************************************************************************* */

  /*** Probe host (SSM vantage point) ***/
  public readonly probeInstance: ec2.Instance;
  public readonly probeSecurityGroup: ec2.SecurityGroup;
  /******************************************************************************* */

  /*** Target host + private DNS ***/
  public readonly targetInstance: ec2.Instance;
  public readonly targetSecurityGroup: ec2.SecurityGroup;
  public readonly targetDnsName: string;
  /******************************************************************************* */

  constructor(scope: Construct, id: string, props: ProbeStackProps) {
    super(scope, id, props);

    const stackName = cdk.Stack.of(this).stackName;

    /*** VPC (10.20.0.0/16) — public + private-isolated subnets, no NAT ***/
    const vpc = this.vpc = new ec2.Vpc(this, 'NetDiagVpc', {
      vpcName: `${stackName}-Vpc`,
      ipAddresses: ec2.IpAddresses.cidr('10.20.0.0/16'),
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        { cidrMask: 24, name: 'Public', subnetType: ec2.SubnetType.PUBLIC },
        { cidrMask: 24, name: 'Private', subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      ],
    });
    /******************************************************************************* */

    /*** Security Groups ***/

    // Probe host — outbound only (reaches SSM endpoints + sends probes to the target).
    this.probeSecurityGroup = new ec2.SecurityGroup(this, 'ProbeSg', {
      vpc,
      securityGroupName: `${stackName}-ProbeSg`,
      description: 'Network diagnostics probe host - egress only',
      allowAllOutbound: true,
    });

    // Target host - reachability from the client tier is governed HERE. The INGRESS RULE
    // descriptions are intentionally REALISTIC (no mention of the demo mechanism) so an
    // investigating agent that reads the SG rules cannot trivially discover this was a staged
    // fault. The fault is injected/cleared by seed.sh/reset.sh at runtime; see those scripts.
    // NOTE: the group-level `description` is IMMUTABLE - changing it forces SG replacement
    // (collides with the explicit name), so it is left as the original; the rule descriptions
    // are where the agent actually looks, and those are neutral.
    this.targetSecurityGroup = new ec2.SecurityGroup(this, 'TargetSg', {
      vpc,
      securityGroupName: `${stackName}-TargetSg`,
      description: 'Probe target - SG rules define reachability (demo fault dial)',
      allowAllOutbound: true,
    });

    this.targetSecurityGroup.addIngressRule(
      this.probeSecurityGroup,
      ec2.Port.tcp(80),
      'HTTP from application tier',
    );
    this.targetSecurityGroup.addIngressRule(
      this.probeSecurityGroup,
      ec2.Port.tcp(5432),
      'PostgreSQL from application tier',
    );
    this.targetSecurityGroup.addIngressRule(
      this.probeSecurityGroup,
      ec2.Port.icmpPing(),
      'ICMP echo from application tier',
    );
    /******************************************************************************* */

    /*** EC2 instance profile (SSM-managed) ***/
    // Both hosts share the same least-privilege managed-instance role: SSM core only.
    const instanceRole = new iam.Role(this, 'InstanceRole', {
      roleName: `${stackName}-InstanceRole`,
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });
    /******************************************************************************* */

    /*** Probe host user-data — install the diagnostic toolset ***/
    const probeUserData = ec2.UserData.forLinux();
    probeUserData.addCommands(
      'set -euxo pipefail',
      'exec > >(tee /var/log/userdata.log) 2>&1',
      '# Network diagnostic tools the MCP tool-router runs via SSM (fixed command set).',
      '#   bind-utils -> dig | nmap-ncat -> nc | traceroute | iproute -> ip | conntrack-tools -> conntrack',
      'dnf install -y bind-utils nmap-ncat traceroute iproute conntrack-tools',
      'echo "probe-tools-installed" > /var/log/netdiag-ready',
    );
    /******************************************************************************* */

    /*** Target host user-data — nginx listening on 80 AND 5432 ***/
    const targetUserData = ec2.UserData.forLinux();
    targetUserData.addCommands(
      'set -euxo pipefail',
      'exec > >(tee /var/log/userdata.log) 2>&1',
      'dnf install -y nginx',
      '# Serve plain HTTP on both 80 and 5432 so TCP reachability to either is a pure',
      '# security-group question (the listener is always up; only the SG changes).',
      'cat > /etc/nginx/conf.d/netdiag.conf <<\'EOF\'',
      'server {',
      '    listen 80 default_server;',
      '    listen 5432;',
      '    server_name _;',
      '    location / { return 200 "netdiag target ok\\n"; }',
      '}',
      'EOF',
      '# Remove the stock default server block to avoid a port 80 conflict.',
      'rm -f /etc/nginx/conf.d/default.conf || true',
      'nginx -t',
      'systemctl enable --now nginx',
      'echo "target-nginx-ready" > /var/log/netdiag-ready',
    );
    /******************************************************************************* */

    /*** Probe host ***/
    this.probeInstance = new ec2.Instance(this, 'ProbeHost', {
      instanceName: `${stackName}-ProbeHost`,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroup: this.probeSecurityGroup,
      role: instanceRole,
      userData: probeUserData,
      associatePublicIpAddress: true,
      blockDevices: [{
        deviceName: '/dev/xvda',
        volume: ec2.BlockDeviceVolume.ebs(8, { volumeType: ec2.EbsDeviceVolumeType.GP3 }),
      }],
    });
    // Least-privilege SSM scope for the MCP Lambda keys off this tag.
    cdk.Tags.of(this.probeInstance).add('NetDiagProbe', 'true');
    /******************************************************************************* */

    /*** Target host ***/
    this.targetInstance = new ec2.Instance(this, 'TargetHost', {
      instanceName: `${stackName}-TargetHost`,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroup: this.targetSecurityGroup,
      role: instanceRole,
      userData: targetUserData,
      associatePublicIpAddress: true,
      blockDevices: [{
        deviceName: '/dev/xvda',
        volume: ec2.BlockDeviceVolume.ebs(8, { volumeType: ec2.EbsDeviceVolumeType.GP3 }),
      }],
    });
    cdk.Tags.of(this.targetInstance).add('NetDiagTarget', 'true');
    /******************************************************************************* */

    /*** Route53 private hosted zone — split-horizon DNS for the target ***/
    const zone = new route53.PrivateHostedZone(this, 'CorpZone', {
      zoneName: 'corp.internal',
      vpc,
    });

    new route53.ARecord(this, 'DbRecord', {
      zone,
      recordName: 'db',
      target: route53.RecordTarget.fromIpAddresses(this.targetInstance.instancePrivateIp),
      ttl: cdk.Duration.seconds(60),
    });

    this.targetDnsName = `db.${zone.zoneName}`;
    /******************************************************************************* */

    /*** Outputs ***/
    new cdk.CfnOutput(this, 'VpcId', { value: vpc.vpcId });
    new cdk.CfnOutput(this, 'ProbeInstanceId', { value: this.probeInstance.instanceId });
    new cdk.CfnOutput(this, 'ProbeSecurityGroupId', { value: this.probeSecurityGroup.securityGroupId });
    new cdk.CfnOutput(this, 'TargetInstanceId', { value: this.targetInstance.instanceId });
    new cdk.CfnOutput(this, 'TargetSecurityGroupId', { value: this.targetSecurityGroup.securityGroupId });
    new cdk.CfnOutput(this, 'TargetPrivateIp', { value: this.targetInstance.instancePrivateIp });
    new cdk.CfnOutput(this, 'TargetDnsName', { value: this.targetDnsName });
    /******************************************************************************* */
  }
}
