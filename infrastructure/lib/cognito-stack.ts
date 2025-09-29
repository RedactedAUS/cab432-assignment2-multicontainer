// cognito-stack.ts - Add this to your CDK infrastructure
// This creates the Cognito User Pool with all Assessment 2 requirements

import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as cdk from 'aws-cdk-lib';

// Add this to your MpegVideoApiStack class

export function createCognitoResources(stack: cdk.Stack, studentId: string) {
  
  // ============================================
  // CORE COGNITO - USER POOL (3 marks)
  // ============================================
  const userPool = new cognito.UserPool(stack, 'VideoApiUserPool', {
    userPoolName: `${studentId}-video-api-users`,
    
    // Self-signup enabled
    selfSignUpEnabled: true,
    
    // Email verification
    signInAliases: {
      username: true,
      email: true
    },
    
    autoVerify: {
      email: true
    },
    
    // Password policy
    passwordPolicy: {
      minLength: 8,
      requireLowercase: true,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
      tempPasswordValidity: cdk.Duration.days(3)
    },
    
    // Email configuration
    email: cognito.UserPoolEmail.withCognito(),
    
    // Standard attributes
    standardAttributes: {
      email: {
        required: true,
        mutable: true
      },
      fullname: {
        required: false,
        mutable: true
      }
    },
    
    // Custom attributes for our app
    customAttributes: {
      'uploadQuota': new cognito.NumberAttribute({ min: 0, max: 1000, mutable: true }),
      'accountTier': new cognito.StringAttribute({ minLen: 1, maxLen: 20, mutable: true })
    },
    
    // MFA configuration (Additional - 2 marks)
    mfa: cognito.Mfa.OPTIONAL,
    mfaSecondFactor: {
      sms: false,
      otp: true  // TOTP authenticator apps
    },
    
    // Account recovery
    accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
    
    // Removal policy
    removalPolicy: cdk.RemovalPolicy.DESTROY
  });

  // ============================================
  // ADDITIONAL COGNITO - USER GROUPS (2 marks)
  // ============================================
  
  // Admin group with elevated permissions
  const adminGroup = new cognito.CfnUserPoolGroup(stack, 'AdminGroup', {
    userPoolId: userPool.userPoolId,
    groupName: 'admin',
    description: 'Administrators with full access',
    precedence: 0
  });

  // Regular users group
  const usersGroup = new cognito.CfnUserPoolGroup(stack, 'UsersGroup', {
    userPoolId: userPool.userPoolId,
    groupName: 'users',
    description: 'Regular users with standard access',
    precedence: 10
  });

  // Premium users group (optional - shows multiple group usage)
  const premiumGroup = new cognito.CfnUserPoolGroup(stack, 'PremiumGroup', {
    userPoolId: userPool.userPoolId,
    groupName: 'premium',
    description: 'Premium users with extended features',
    precedence: 5
  });

  // ============================================
  // USER POOL CLIENT
  // ============================================
  const userPoolClient = new cognito.UserPoolClient(stack, 'VideoApiUserPoolClient', {
    userPool: userPool,
    userPoolClientName: `${studentId}-video-api-client`,
    
    // Auth flows
    authFlows: {
      userPassword: true,
      userSrp: true,
      custom: false,
      adminUserPassword: true
    },
    
    // OAuth settings for federated login
    oAuth: {
      flows: {
        authorizationCodeGrant: true,
        implicitCodeGrant: true
      },
      scopes: [
        cognito.OAuthScope.EMAIL,
        cognito.OAuthScope.OPENID,
        cognito.OAuthScope.PROFILE,
        cognito.OAuthScope.COGNITO_ADMIN
      ],
      callbackUrls: [
        'http://localhost:3001/auth/callback',
        `https://${studentId}-mpeg-video.cab432.com/auth/callback`,
        `https://${studentId}-mpeg-video.cab432.com:3001/auth/callback`
      ],
      logoutUrls: [
        'http://localhost:3001',
        `https://${studentId}-mpeg-video.cab432.com`,
        `https://${studentId}-mpeg-video.cab432.com:3001`
      ]
    },
    
    // Token validity
    accessTokenValidity: cdk.Duration.hours(1),
    idTokenValidity: cdk.Duration.hours(1),
    refreshTokenValidity: cdk.Duration.days(30),
    
    // Prevent user existence errors
    preventUserExistenceErrors: true,
    
    // Read and write attributes
    readAttributes: new cognito.ClientAttributes()
      .withStandardAttributes({
        email: true,
        emailVerified: true,
        fullname: true
      })
      .withCustomAttributes('uploadQuota', 'accountTier'),
    
    writeAttributes: new cognito.ClientAttributes()
      .withStandardAttributes({
        email: true,
        fullname: true
      })
      .withCustomAttributes('uploadQuota', 'accountTier')
  });

  // ============================================
  // ADDITIONAL COGNITO - FEDERATED IDENTITIES (2 marks)
  // GOOGLE OAUTH PROVIDER
  // ============================================
  
  // Note: You need to create a Google OAuth app first:
  // 1. Go to https://console.developers.google.com
  // 2. Create a new project or select existing
  // 3. Enable Google+ API
  // 4. Create OAuth 2.0 credentials
  // 5. Add authorized redirect URIs from Cognito
  
  const googleProvider = new cognito.UserPoolIdentityProviderGoogle(stack, 'GoogleProvider', {
    userPool: userPool,
    clientId: 'YOUR_GOOGLE_CLIENT_ID', // Replace with actual Google OAuth client ID
    clientSecret: 'YOUR_GOOGLE_CLIENT_SECRET', // Replace with actual secret (better: store in Secrets Manager)
    
    scopes: ['profile', 'email', 'openid'],
    
    attributeMapping: {
      email: cognito.ProviderAttribute.GOOGLE_EMAIL,
      givenName: cognito.ProviderAttribute.GOOGLE_GIVEN_NAME,
      familyName: cognito.ProviderAttribute.GOOGLE_FAMILY_NAME,
      profilePicture: cognito.ProviderAttribute.GOOGLE_PICTURE,
      custom: {
        'email_verified': cognito.ProviderAttribute.other('email_verified')
      }
    }
  });

  // Make client depend on provider
  userPoolClient.node.addDependency(googleProvider);

  // ============================================
  // COGNITO DOMAIN (for Hosted UI)
  // ============================================
  const domain = userPool.addDomain('CognitoDomain', {
    cognitoDomain: {
      domainPrefix: `${studentId}-video-api`
    }
  });

  // ============================================
  // PARAMETER STORE - Store Cognito Configuration
  // ============================================
  new ssm.StringParameter(stack, 'CognitoUserPoolIdParam', {
    parameterName: `/${studentId}/app/cognito-user-pool-id`,
    stringValue: userPool.userPoolId,
    description: 'Cognito User Pool ID',
    tier: ssm.ParameterTier.STANDARD
  });

  new ssm.StringParameter(stack, 'CognitoClientIdParam', {
    parameterName: `/${studentId}/app/cognito-client-id`,
    stringValue: userPoolClient.userPoolClientId,
    description: 'Cognito App Client ID',
    tier: ssm.ParameterTier.STANDARD
  });

  new ssm.StringParameter(stack, 'CognitoDomainParam', {
    parameterName: `/${studentId}/app/cognito-domain`,
    stringValue: domain.domainName,
    description: 'Cognito Hosted UI Domain',
    tier: ssm.ParameterTier.STANDARD
  });

  // ============================================
  // OUTPUTS
  // ============================================
  new cdk.CfnOutput(stack, 'UserPoolId', {
    value: userPool.userPoolId,
    description: 'Cognito User Pool ID',
    exportName: `${studentId}-UserPoolId`
  });

  new cdk.CfnOutput(stack, 'UserPoolClientId', {
    value: userPoolClient.userPoolClientId,
    description: 'Cognito User Pool Client ID',
    exportName: `${studentId}-UserPoolClientId`
  });

  new cdk.CfnOutput(stack, 'CognitoHostedUIUrl', {
    value: `https://${domain.domainName}.auth.${stack.region}.amazoncognito.com`,
    description: 'Cognito Hosted UI URL',
    exportName: `${studentId}-CognitoHostedUI`
  });

  new cdk.CfnOutput(stack, 'GoogleLoginUrl', {
    value: `https://${domain.domainName}.auth.${stack.region}.amazoncognito.com/oauth2/authorize?client_id=${userPoolClient.userPoolClientId}&response_type=code&scope=email+openid+profile&redirect_uri=https://${studentId}-mpeg-video.cab432.com/auth/callback`,
    description: 'Google Federated Login URL'
  });

  return {
    userPool,
    userPoolClient,
    domain,
    adminGroup,
    usersGroup,
    premiumGroup,
    googleProvider
  };
}
