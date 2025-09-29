// cognito-auth.js - AWS Cognito Authentication with Google Federated Identity
// Assessment 2: Demonstrates Cognito core + federated identities + groups + MFA

const AWS = require('aws-sdk');
const { 
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  SignUpCommand,
  ConfirmSignUpCommand,
  AdminGetUserCommand,
  AdminAddUserToGroupCommand,
  AdminRemoveUserFromGroupCommand,
  AdminListGroupsForUserCommand,
  AdminSetUserMFAPreferenceCommand,
  AssociateSoftwareTokenCommand,
  VerifySoftwareTokenCommand,
  GetUserCommand
} = require('@aws-sdk/client-cognito-identity-provider');

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

class CognitoAuthService {
  constructor() {
    this.region = process.env.AWS_REGION || 'ap-southeast-2';
    this.userPoolId = process.env.COGNITO_USER_POOL_ID;
    this.clientId = process.env.COGNITO_CLIENT_ID;
    this.studentId = process.env.STUDENT_ID || 'n11538082';
    
    // Initialize Cognito client
    this.cognitoClient = new CognitoIdentityProviderClient({
      region: this.region
    });

    // JWKS client for token verification
    this.jwksClient = jwksClient({
      jwksUri: `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}/.well-known/jwks.json`,
      cache: true,
      cacheMaxAge: 600000
    });

    console.log('🔐 Cognito Auth Service initialized');
    console.log(`   User Pool: ${this.userPoolId}`);
    console.log(`   Client ID: ${this.clientId}`);
    console.log(`   Region: ${this.region}`);
  }

  // ============================================
  // CORE COGNITO - USER SIGNUP
  // ============================================
  async signUp(username, password, email, attributes = {}) {
    try {
      console.log(`📝 Signing up new user: ${username}`);

      const command = new SignUpCommand({
        ClientId: this.clientId,
        Username: username,
        Password: password,
        UserAttributes: [
          { Name: 'email', Value: email },
          ...Object.entries(attributes).map(([key, value]) => ({
            Name: key,
            Value: value
          }))
        ]
      });

      const response = await this.cognitoClient.send(command);
      
      console.log(`✅ User signup successful: ${username}`);
      console.log(`   User Sub: ${response.UserSub}`);
      console.log(`   Confirmation required: ${!response.UserConfirmed}`);

      return {
        success: true,
        userSub: response.UserSub,
        userConfirmed: response.UserConfirmed,
        codeDeliveryDetails: response.CodeDeliveryDetails,
        message: response.UserConfirmed 
          ? 'User registered and confirmed' 
          : 'User registered - verification code sent'
      };

    } catch (error) {
      console.error('❌ Signup error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // CORE COGNITO - CONFIRM SIGNUP
  // ============================================
  async confirmSignUp(username, confirmationCode) {
    try {
      console.log(`✉️ Confirming user: ${username}`);

      const command = new ConfirmSignUpCommand({
        ClientId: this.clientId,
        Username: username,
        ConfirmationCode: confirmationCode
      });

      await this.cognitoClient.send(command);
      
      console.log(`✅ User confirmed: ${username}`);
      
      return {
        success: true,
        message: 'Email verified successfully'
      };

    } catch (error) {
      console.error('❌ Confirmation error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // CORE COGNITO - USER LOGIN (Username/Password)
  // ============================================
  async login(username, password) {
    try {
      console.log(`🔑 Authenticating user: ${username}`);

      const command = new InitiateAuthCommand({
        ClientId: this.clientId,
        AuthFlow: 'USER_PASSWORD_AUTH',
        AuthParameters: {
          USERNAME: username,
          PASSWORD: password
        }
      });

      const response = await this.cognitoClient.send(command);

      // Check if MFA is required
      if (response.ChallengeName === 'SOFTWARE_TOKEN_MFA') {
        console.log('🔐 MFA challenge required');
        return {
          success: true,
          challengeName: response.ChallengeName,
          session: response.Session,
          requiresMFA: true,
          message: 'MFA code required'
        };
      }

      // Check if new password required (first login)
      if (response.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
        console.log('🔄 New password required');
        return {
          success: true,
          challengeName: response.ChallengeName,
          session: response.Session,
          requiresNewPassword: true,
          message: 'New password required'
        };
      }

      const tokens = response.AuthenticationResult;
      const decodedToken = jwt.decode(tokens.IdToken);
      
      console.log(`✅ Login successful: ${username}`);
      console.log(`   User Groups: ${decodedToken['cognito:groups'] || 'none'}`);

      return {
        success: true,
        tokens: {
          idToken: tokens.IdToken,
          accessToken: tokens.AccessToken,
          refreshToken: tokens.RefreshToken,
          expiresIn: tokens.ExpiresIn
        },
        user: {
          username: decodedToken['cognito:username'],
          email: decodedToken.email,
          sub: decodedToken.sub,
          groups: decodedToken['cognito:groups'] || []
        }
      };

    } catch (error) {
      console.error('❌ Login error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // ADDITIONAL COGNITO - MFA SETUP
  // ============================================
  async setupMFA(accessToken) {
    try {
      console.log('🔐 Setting up MFA...');

      const command = new AssociateSoftwareTokenCommand({
        AccessToken: accessToken
      });

      const response = await this.cognitoClient.send(command);
      
      console.log('✅ MFA setup initiated');

      return {
        success: true,
        secretCode: response.SecretCode,
        qrCodeUrl: this.generateQRCodeUrl(response.SecretCode),
        message: 'Scan QR code with authenticator app'
      };

    } catch (error) {
      console.error('❌ MFA setup error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // ADDITIONAL COGNITO - VERIFY MFA SETUP
  // ============================================
  async verifyMFASetup(accessToken, mfaCode) {
    try {
      console.log('🔐 Verifying MFA setup...');

      // Verify the token
      const verifyCommand = new VerifySoftwareTokenCommand({
        AccessToken: accessToken,
        UserCode: mfaCode
      });

      await this.cognitoClient.send(verifyCommand);

      // Set MFA preference to required
      const preferenceCommand = new AdminSetUserMFAPreferenceCommand({
        UserPoolId: this.userPoolId,
        Username: jwt.decode(accessToken)['cognito:username'],
        SoftwareTokenMfaSettings: {
          Enabled: true,
          PreferredMfa: true
        }
      });

      await this.cognitoClient.send(preferenceCommand);
      
      console.log('✅ MFA enabled successfully');

      return {
        success: true,
        message: 'MFA enabled successfully'
      };

    } catch (error) {
      console.error('❌ MFA verification error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // ADDITIONAL COGNITO - RESPOND TO MFA CHALLENGE
  // ============================================
  async respondToMFAChallenge(username, mfaCode, session) {
    try {
      console.log(`🔐 Verifying MFA code for: ${username}`);

      const command = new RespondToAuthChallengeCommand({
        ClientId: this.clientId,
        ChallengeName: 'SOFTWARE_TOKEN_MFA',
        Session: session,
        ChallengeResponses: {
          USERNAME: username,
          SOFTWARE_TOKEN_MFA_CODE: mfaCode
        }
      });

      const response = await this.cognitoClient.send(command);
      const tokens = response.AuthenticationResult;
      const decodedToken = jwt.decode(tokens.IdToken);
      
      console.log(`✅ MFA verification successful: ${username}`);

      return {
        success: true,
        tokens: {
          idToken: tokens.IdToken,
          accessToken: tokens.AccessToken,
          refreshToken: tokens.RefreshToken,
          expiresIn: tokens.ExpiresIn
        },
        user: {
          username: decodedToken['cognito:username'],
          email: decodedToken.email,
          sub: decodedToken.sub,
          groups: decodedToken['cognito:groups'] || []
        }
      };

    } catch (error) {
      console.error('❌ MFA challenge error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // ADDITIONAL COGNITO - FEDERATED LOGIN (Google)
  // This is handled client-side with Cognito Hosted UI
  // The backend just validates the token
  // ============================================
  async handleFederatedLogin(idToken) {
    try {
      console.log('🌐 Processing federated login...');

      // Verify the token
      const verified = await this.verifyToken(idToken);
      
      if (!verified.valid) {
        throw new Error('Invalid federated token');
      }

      console.log(`✅ Federated login successful: ${verified.user.email}`);
      console.log(`   Provider: ${verified.user.identities?.[0]?.providerName || 'Google'}`);

      return {
        success: true,
        user: verified.user,
        message: 'Federated authentication successful'
      };

    } catch (error) {
      console.error('❌ Federated login error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // ADDITIONAL COGNITO - USER GROUPS
  // ============================================
  async addUserToGroup(username, groupName) {
    try {
      console.log(`👥 Adding ${username} to group: ${groupName}`);

      const command = new AdminAddUserToGroupCommand({
        UserPoolId: this.userPoolId,
        Username: username,
        GroupName: groupName
      });

      await this.cognitoClient.send(command);
      
      console.log(`✅ User added to group: ${groupName}`);

      return {
        success: true,
        message: `User added to ${groupName} group`
      };

    } catch (error) {
      console.error('❌ Add to group error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  async removeUserFromGroup(username, groupName) {
    try {
      console.log(`👥 Removing ${username} from group: ${groupName}`);

      const command = new AdminRemoveUserFromGroupCommand({
        UserPoolId: this.userPoolId,
        Username: username,
        GroupName: groupName
      });

      await this.cognitoClient.send(command);
      
      console.log(`✅ User removed from group: ${groupName}`);

      return {
        success: true,
        message: `User removed from ${groupName} group`
      };

    } catch (error) {
      console.error('❌ Remove from group error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  async getUserGroups(username) {
    try {
      const command = new AdminListGroupsForUserCommand({
        UserPoolId: this.userPoolId,
        Username: username
      });

      const response = await this.cognitoClient.send(command);
      
      return {
        success: true,
        groups: response.Groups.map(g => ({
          name: g.GroupName,
          description: g.Description,
          precedence: g.Precedence
        }))
      };

    } catch (error) {
      console.error('❌ Get user groups error:', error.message);
      throw this.handleCognitoError(error);
    }
  }

  // ============================================
  // TOKEN VERIFICATION
  // ============================================
  async verifyToken(token) {
    try {
      // Decode token header to get kid
      const decoded = jwt.decode(token, { complete: true });
      
      if (!decoded) {
        throw new Error('Invalid token format');
      }

      // Get signing key
      const key = await this.getSigningKey(decoded.header.kid);
      
      // Verify token
      const verified = jwt.verify(token, key, {
        algorithms: ['RS256'],
        issuer: `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}`
      });

      return {
        valid: true,
        user: {
          username: verified['cognito:username'],
          email: verified.email,
          sub: verified.sub,
          groups: verified['cognito:groups'] || [],
          identities: verified.identities,
          emailVerified: verified.email_verified
        }
      };

    } catch (error) {
      console.error('❌ Token verification error:', error.message);
      return {
        valid: false,
        error: error.message
      };
    }
  }

  // ============================================
  // HELPER METHODS
  // ============================================
  async getSigningKey(kid) {
    return new Promise((resolve, reject) => {
      this.jwksClient.getSigningKey(kid, (err, key) => {
        if (err) {
          reject(err);
        } else {
          const signingKey = key.getPublicKey();
          resolve(signingKey);
        }
      });
    });
  }

  generateQRCodeUrl(secretCode) {
    const appName = 'MPEG-Video-API';
    const username = 'user'; // This should be replaced with actual username
    const otpauthUrl = `otpauth://totp/${appName}:${username}?secret=${secretCode}&issuer=${appName}`;
    return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthUrl)}`;
  }

  handleCognitoError(error) {
    const errorMap = {
      'UserNotFoundException': {
        status: 404,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      },
      'NotAuthorizedException': {
        status: 401,
        message: 'Incorrect username or password',
        code: 'INVALID_CREDENTIALS'
      },
      'UserNotConfirmedException': {
        status: 403,
        message: 'User email not verified',
        code: 'EMAIL_NOT_VERIFIED'
      },
      'CodeMismatchException': {
        status: 400,
        message: 'Invalid verification code',
        code: 'INVALID_CODE'
      },
      'ExpiredCodeException': {
        status: 400,
        message: 'Verification code expired',
        code: 'CODE_EXPIRED'
      },
      'InvalidPasswordException': {
        status: 400,
        message: 'Password does not meet requirements',
        code: 'INVALID_PASSWORD'
      },
      'UsernameExistsException': {
        status: 400,
        message: 'Username already exists',
        code: 'USERNAME_EXISTS'
      },
      'TooManyRequestsException': {
        status: 429,
        message: 'Too many requests, please try again later',
        code: 'RATE_LIMIT'
      }
    };

    const errorInfo = errorMap[error.name] || {
      status: 500,
      message: error.message || 'Authentication error',
      code: 'COGNITO_ERROR'
    };

    return {
      ...errorInfo,
      originalError: error.name
    };
  }

  // ============================================
  // ASSESSMENT 2 - GET CONFIGURATION INFO
  // ============================================
  getAuthConfiguration() {
    return {
      region: this.region,
      userPoolId: this.userPoolId,
      clientId: this.clientId,
      hostedUIUrl: `https://${this.studentId}-video-api.auth.${this.region}.amazoncognito.com`,
      federatedIdentityProviders: ['Google'],
      mfaEnabled: true,
      groupsEnabled: true,
      assessment2Criteria: {
        core_authentication: 'Cognito user pool with signup, login, verification',
        federated_identities: 'Google OAuth2 via Cognito Hosted UI',
        user_groups: 'Admin and User groups with permission checking',
        mfa: 'TOTP-based multi-factor authentication'
      }
    };
  }
}

module.exports = new CognitoAuthService();
