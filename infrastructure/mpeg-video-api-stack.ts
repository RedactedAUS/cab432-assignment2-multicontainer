import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as iam from 'aws-cdk-lib/aws-iam';

export class MpegVideoApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const studentId = 'n11538082';
    // VPC for our resources
    const vpc = new ec2.Vpc(this, 'MpegApiVpc', {
      maxAzs: 2,
      natGateways: 1,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'public',
          subnetType: ec2.SubnetType.PUBLIC,
        },
        {
          cidrMask: 24,
          name: 'private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        },
      ],
    });

    // Security Group for RDS
    const rdsSecurityGroup = new ec2.SecurityGroup(this, 'RdsSecurityGroup', {
      vpc,
      description: 'Security group for PostgreSQL RDS',
      allowAllOutbound: true,
    });

    // Security Group for ElastiCache
    const cacheSecurityGroup = new ec2.SecurityGroup(this, 'CacheSecurityGroup', {
      vpc,
      description: 'Security group for ElastiCache Redis',
      allowAllOutbound: true,
    });

    // Security Group for EC2
    const ec2SecurityGroup = new ec2.SecurityGroup(this, 'Ec2SecurityGroup', {
      vpc,
      description: 'Security group for EC2 instances',
      allowAllOutbound: true,
    });

    // Allow EC2 to access RDS
    rdsSecurityGroup.addIngressRule(
      ec2SecurityGroup,
      ec2.Port.tcp(5432),
      'Allow EC2 access to PostgreSQL'
    );

    // Allow EC2 to access ElastiCache
    cacheSecurityGroup.addIngressRule(
      ec2SecurityGroup,
      ec2.Port.tcp(6379),
      'Allow EC2 access to Redis'
    );

    // Allow HTTP/HTTPS traffic to EC2
    ec2SecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(80),
      'Allow HTTP traffic'
    );
    ec2SecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Allow HTTPS traffic'
    );
    ec2SecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(3000),
      'Allow application traffic'
    );
    ec2SecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(3001),
      'Allow application traffic alt port'
    );
    ec2SecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(22),
      'Allow SSH access'
    );

    // S3 Bucket for video storage (Second Data Persistence Service)
    const videoBucket = new s3.Bucket(this, 'VideoStorageBucket', {
      bucketName: `cab432-${studentId}-videos`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
      lifecycleRules: [
        {
          id: 'delete-incomplete-uploads',
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(1),
        },
        {
          id: 'transition-to-ia',
          transitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: cdk.Duration.days(30),
            },
          ],
        },
      ],
      cors: [
        {
          allowedMethods: [
            s3.HttpMethods.GET,
            s3.HttpMethods.POST,
            s3.HttpMethods.PUT,
            s3.HttpMethods.DELETE,
            s3.HttpMethods.HEAD,
          ],
          allowedOrigins: ['*'],
          allowedHeaders: ['*'],
          exposedHeaders: ['ETag'],
          maxAge: 3000,
        },
      ],
    });

    // Database password secret (Secrets Manager)
    const dbPassword = new secretsmanager.Secret(this, 'DatabasePassword', {
      secretName: `${studentId}/database/password`,
      description: 'PostgreSQL database password',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: 'postgres' }),
        generateStringKey: 'password',
        excludeCharacters: '"@/\\',
        includeSpace: false,
        passwordLength: 32,
      },
    });

    // RDS PostgreSQL Database (First Data Persistence Service)
    const database = new rds.DatabaseInstance(this, 'PostgreSQLDatabase', {
      instanceIdentifier: `${studentId}-mpeg-video-db`,
      engine: rds.DatabaseInstanceEngine.postgres({
        version: rds.PostgresEngineVersion.VER_15_4,
      }),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
      securityGroups: [rdsSecurityGroup],
      databaseName: 'mpegapi',
      credentials: rds.Credentials.fromSecret(dbPassword),
      backupRetention: cdk.Duration.days(7),
      deleteAutomatedBackups: true,
      deletionProtection: false,
      multiAz: false,
      storageEncrypted: true,
      monitoringInterval: cdk.Duration.seconds(60),
      enablePerformanceInsights: true,
    });

    // Add tags using CDK Tags
    cdk.Tags.of(database).add('purpose', 'assessment-2');
    cdk.Tags.of(database).add('qut-username', `${studentId}@qut.edu.au`);

    // DynamoDB Table for session management (Third Data Service - 3 marks)
    const sessionTable = new dynamodb.Table(this, 'SessionTable', {
      tableName: `${studentId}-video-sessions`,
      partitionKey: { name: 'sessionId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for user lookup
    sessionTable.addGlobalSecondaryIndex({
      indexName: 'UserIndex',
      partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
    });

    // ElastiCache Subnet Group
    const cacheSubnetGroup = new elasticache.CfnSubnetGroup(this, 'CacheSubnetGroup', {
      description: 'Subnet group for ElastiCache',
      subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
      cacheSubnetGroupName: `${studentId}-cache-subnet-group`,
    });

    // ElastiCache Redis Cluster for caching (In-memory Caching - 3 marks)
    const redisCluster = new elasticache.CfnCacheCluster(this, 'RedisCluster', {
      cacheNodeType: 'cache.t3.micro',
      engine: 'redis',
      numCacheNodes: 1,
      clusterName: `${studentId}-video-cache`,
      cacheSubnetGroupName: cacheSubnetGroup.cacheSubnetGroupName,
      vpcSecurityGroupIds: [cacheSecurityGroup.securityGroupId],
      engineVersion: '7.0',
    });
    redisCluster.addDependency(cacheSubnetGroup);

    // External API Keys Secret (Secrets Manager - 2 marks)
    const apiKeysSecret = new secretsmanager.Secret(this, 'ExternalApiKeys', {
      secretName: `${studentId}/external-api-keys`,
      description: 'External API keys for OMDB and other services',
      secretStringValue: cdk.SecretValue.unsafePlainText(JSON.stringify({
        omdb_api_key: 'trilogy',
        jwt_secret: 'your-super-secret-jwt-key-here',
        encryption_key: 'your-encryption-key-here'
      })),
    });

    // Parameter Store values (Parameter Store - 2 marks)
    const parameters = [
      {
        name: `/${studentId}/app/database-url`,
        value: `postgresql://${database.instanceEndpoint.hostname}:${database.instanceEndpoint.port}/mpegapi`,
        description: 'Database connection URL'
      },
      {
        name: `/${studentId}/app/redis-url`,
        value: `redis://${redisCluster.attrRedisEndpointAddress}:${redisCluster.attrRedisEndpointPort}`,
        description: 'Redis connection URL'
      },
      {
        name: `/${studentId}/app/s3-bucket`,
        value: videoBucket.bucketName,
        description: 'S3 bucket name for video storage'
      },
      {
        name: `/${studentId}/app/aws-region`,
        value: this.region,
        description: 'AWS region'
      },
      {
        name: `/${studentId}/app/dynamodb-table`,
        value: sessionTable.tableName,
        description: 'DynamoDB table name for sessions'
      },
      {
        name: `/${studentId}/app/base-url`,
        value: `https://${studentId}-mpeg-video.cab432.com`,
        description: 'Application base URL'
      }
    ];

    parameters.forEach((param, index) => {
      new ssm.StringParameter(this, `Parameter${index}`, {
        parameterName: param.name,
        stringValue: param.value,
        description: param.description,
        tier: ssm.ParameterTier.STANDARD,
      });
    });

    // IAM Role for EC2 instances
    const ec2Role = new iam.Role(this, 'Ec2InstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'IAM role for MPEG Video API EC2 instances',
    });

    // Add permissions for S3 (S3 Pre-signed URLs - 2 marks)
    videoBucket.grantReadWrite(ec2Role);

    // Add permissions for DynamoDB
    sessionTable.grantReadWriteData(ec2Role);

    // Add permissions for Parameter Store
    ec2Role.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'ssm:GetParameter',
        'ssm:GetParameters',
        'ssm:GetParametersByPath',
      ],
      resources: [
        `arn:aws:ssm:${this.region}:${this.account}:parameter/${studentId}/*`,
      ],
    }));

    // Add permissions for Secrets Manager
    dbPassword.grantRead(ec2Role);
    apiKeysSecret.grantRead(ec2Role);

    // Instance Profile
    const instanceProfile = new iam.CfnInstanceProfile(this, 'Ec2InstanceProfile', {
      roles: [ec2Role.roleName],
      instanceProfileName: `${studentId}-ec2-instance-profile`,
    });

    // Outputs
    new cdk.CfnOutput(this, 'DatabaseEndpoint', {
      value: database.instanceEndpoint.hostname,
      description: 'PostgreSQL database endpoint',
    });

    new cdk.CfnOutput(this, 'RedisEndpoint', {
      value: redisCluster.attrRedisEndpointAddress,
      description: 'Redis cluster endpoint',
    });

    new cdk.CfnOutput(this, 'S3BucketName', {
      value: videoBucket.bucketName,
      description: 'S3 bucket name for video storage',
    });

    new cdk.CfnOutput(this, 'DynamoDBTableName', {
      value: sessionTable.tableName,
      description: 'DynamoDB table name for sessions',
    });

    new cdk.CfnOutput(this, 'EC2SecurityGroupId', {
      value: ec2SecurityGroup.securityGroupId,
      description: 'EC2 security group ID',
    });

    new cdk.CfnOutput(this, 'EC2InstanceProfile', {
      value: instanceProfile.ref,
      description: 'EC2 instance profile name',
    });

    new cdk.CfnOutput(this, 'VpcId', {
      value: vpc.vpcId,
      description: 'VPC ID',
    });
  }
}
