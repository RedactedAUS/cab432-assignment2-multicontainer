// cognito-routes.js - Express Routes for Cognito Authentication
// Add these routes to your index.js

const express = require('express');
const router = express.Router();
const cognitoAuth = require('./cognito-auth');

// ============================================
// CORE COGNITO - USER SIGNUP
// ============================================
router.post('/auth/signup', async (req, res) => {
  try {
    const { username, password, email, fullname } = req.body;

    // Validation
    if (!username || !password || !email) {
      return res.status(400).json({
        error: 'Username, password, and email are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Sign up user
    const result = await cognitoAuth.signUp(username, password, email, {
      name: fullname || ''
    });

    res.status(201).json({
      success: true,
      message: result.message,
      userSub: result.userSub,
      userConfirmed: result.userConfirmed,
      assessment2Demo: {
        core_criterion: 'Cognito Authentication - User Signup',
        userPoolIntegration: 'AWS Cognito User Pool',
        emailVerification: 'Verification code sent to email'
      }
    });

  } catch (error) {
    console.error('Signup route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// CORE COGNITO - CONFIRM SIGNUP
// ============================================
router.post('/auth/confirm', async (req, res) => {
  try {
    const { username, code } = req.body;

    if (!username || !code) {
      return res.status(400).json({
        error: 'Username and confirmation code are required',
        code: 'MISSING_FIELDS'
      });
    }

    const result = await cognitoAuth.confirmSignUp(username, code);

    res.json({
      success: true,
      message: result.message,
      assessment2Demo: {
        core_criterion: 'Cognito Authentication - Email Verification',
        emailVerified: true
      }
    });

  } catch (error) {
    console.error('Confirmation route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// CORE COGNITO - LOGIN
// ============================================
router.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required',
        code: 'MISSING_FIELDS'
      });
    }

    const result = await cognitoAuth.login(username, password);

    // If MFA is required
    if (result.requiresMFA) {
      return res.json({
        success: true,
        requiresMFA: true,
        session: result.session,
        message: result.message,
        assessment2Demo: {
          additional_criterion: 'Cognito MFA',
          mfaType: 'SOFTWARE_TOKEN_MFA'
        }
      });
    }

    // If new password required
    if (result.requiresNewPassword) {
      return res.json({
        success: true,
        requiresNewPassword: true,
        session: result.session,
        message: result.message
      });
    }

    // Successful login
    res.json({
      success: true,
      tokens: result.tokens,
      user: result.user,
      assessment2Demo: {
        core_criterion: 'Cognito Authentication - Login',
        tokenType: 'Cognito ID Token (JWT)',
        userGroups: result.user.groups,
        authentication: 'Username/Password via Cognito'
      }
    });

  } catch (error) {
    console.error('Login route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// ADDITIONAL COGNITO - FEDERATED LOGIN CALLBACK
// ============================================
router.get('/auth/callback', async (req, res) => {
  try {
    const { code, error, error_description } = req.query;

    if (error) {
      console.error('OAuth error:', error, error_description);
      return res.redirect(`/?error=${error}&error_description=${encodeURIComponent(error_description)}`);
    }

    if (!code) {
      return res.status(400).json({
        error: 'Authorization code missing',
        code: 'MISSING_CODE'
      });
    }

    // Exchange authorization code for tokens
const tokenEndpoint = `https://${cognitoAuth.studentId}-video-api.auth.${cognitoAuth.region}.amazoncognito.com/oauth2/token`;

const params = new URLSearchParams({
  grant_type: 'authorization_code',
  client_id: cognitoAuth.clientId,
  code: code,
  redirect_uri: `https://${process.env.STUDENT_ID}-mpeg-video.cab432.com/api/v1/auth/callback`
});

console.log('Token exchange request:', {
  endpoint: tokenEndpoint,
  params: params.toString()
});


    // Add client secret for confidential client flow
   // if (process.env.COGNITO_CLIENT_SECRET) {
    //  params.append('client_secret', process.env.COGNITO_CLIENT_SECRET);
  //  }

const tokenResponse = await fetch(tokenEndpoint, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: params.toString()
});

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text();
      console.error('Token exchange failed:', errorData);
      return res.redirect(`/?error=token_exchange_failed&details=${encodeURIComponent(errorData)}`);
    }

    const tokens = await tokenResponse.json();
    
    // Verify the ID token
    const verified = await cognitoAuth.verifyToken(tokens.id_token);
    
    if (!verified.valid) {
      return res.redirect('/?error=invalid_token');
    }

    // Successful Google login - redirect to frontend with token
    res.redirect(`/?id_token=${tokens.id_token}&access_token=${tokens.access_token}&login_type=google`);

  } catch (error) {
    console.error('Callback route error:', error);
    res.redirect(`/?error=auth_failed&message=${encodeURIComponent(error.message)}`);
  }
});

// ============================================
// ADDITIONAL COGNITO - FEDERATED TOKEN VALIDATION
// ============================================
router.post('/auth/federated', async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({
        error: 'ID token required',
        code: 'MISSING_TOKEN'
      });
    }

    const result = await cognitoAuth.handleFederatedLogin(idToken);

    res.json({
      success: true,
      user: result.user,
      message: result.message,
      assessment2Demo: {
        additional_criterion: 'Cognito Federated Identities',
        provider: result.user.identities?.[0]?.providerName || 'Google',
        authentication: 'Google OAuth2 via Cognito',
        socialLogin: true
      }
    });

  } catch (error) {
    console.error('Federated login route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// ADDITIONAL COGNITO - SETUP MFA
// ============================================
router.post('/auth/mfa/setup', authenticateCognito, async (req, res) => {
  try {
    const accessToken = req.user.accessToken;

    const result = await cognitoAuth.setupMFA(accessToken);

    res.json({
      success: true,
      secretCode: result.secretCode,
      qrCodeUrl: result.qrCodeUrl,
      message: result.message,
      assessment2Demo: {
        additional_criterion: 'Cognito MFA',
        mfaType: 'TOTP (Time-based One-Time Password)',
        instructions: 'Scan QR code with Google Authenticator or similar app'
      }
    });

  } catch (error) {
    console.error('MFA setup route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// ADDITIONAL COGNITO - VERIFY MFA SETUP
// ============================================
router.post('/auth/mfa/verify', authenticateCognito, async (req, res) => {
  try {
    const { mfaCode } = req.body;
    const accessToken = req.user.accessToken;

    if (!mfaCode) {
      return res.status(400).json({
        error: 'MFA code required',
        code: 'MISSING_CODE'
      });
    }

    const result = await cognitoAuth.verifyMFASetup(accessToken, mfaCode);

    res.json({
      success: true,
      message: result.message,
      assessment2Demo: {
        additional_criterion: 'Cognito MFA Enabled',
        mfaStatus: 'Active',
        requiresMFA: true
      }
    });

  } catch (error) {
    console.error('MFA verify route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// ADDITIONAL COGNITO - RESPOND TO MFA CHALLENGE
// ============================================
router.post('/auth/mfa/challenge', async (req, res) => {
  try {
    const { username, mfaCode, session } = req.body;

    if (!username || !mfaCode || !session) {
      return res.status(400).json({
        error: 'Username, MFA code, and session are required',
        code: 'MISSING_FIELDS'
      });
    }

    const result = await cognitoAuth.respondToMFAChallenge(username, mfaCode, session);

    res.json({
      success: true,
      tokens: result.tokens,
      user: result.user,
      assessment2Demo: {
        additional_criterion: 'Cognito MFA Authentication',
        mfaVerified: true,
        securityLevel: 'Two-Factor Authentication'
      }
    });

  } catch (error) {
    console.error('MFA challenge route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// ADDITIONAL COGNITO - USER GROUPS MANAGEMENT
// ============================================
router.post('/auth/groups/add', authenticateCognito, requireAdmin, async (req, res) => {
  try {
    const { username, groupName } = req.body;

    if (!username || !groupName) {
      return res.status(400).json({
        error: 'Username and group name are required',
        code: 'MISSING_FIELDS'
      });
    }

    const result = await cognitoAuth.addUserToGroup(username, groupName);

    res.json({
      success: true,
      message: result.message,
      assessment2Demo: {
        additional_criterion: 'Cognito User Groups',
        action: 'User added to group',
        groupManagement: 'Admin permission required'
      }
    });

  } catch (error) {
    console.error('Add to group route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

router.post('/auth/groups/remove', authenticateCognito, requireAdmin, async (req, res) => {
  try {
    const { username, groupName } = req.body;

    if (!username || !groupName) {
      return res.status(400).json({
        error: 'Username and group name are required',
        code: 'MISSING_FIELDS'
      });
    }

    const result = await cognitoAuth.removeUserFromGroup(username, groupName);

    res.json({
      success: true,
      message: result.message,
      assessment2Demo: {
        additional_criterion: 'Cognito User Groups',
        action: 'User removed from group'
      }
    });

  } catch (error) {
    console.error('Remove from group route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

router.get('/auth/groups/:username', authenticateCognito, async (req, res) => {
  try {
    const { username } = req.params;

    // Check if user can access this info (self or admin)
    if (req.user.username !== username && !req.user.groups.includes('admin')) {
      return res.status(403).json({
        error: 'Not authorized to view this user\'s groups',
        code: 'FORBIDDEN'
      });
    }

    const result = await cognitoAuth.getUserGroups(username);

    res.json({
      success: true,
      groups: result.groups,
      assessment2Demo: {
        additional_criterion: 'Cognito User Groups',
        groupBasedPermissions: true
      }
    });

  } catch (error) {
    console.error('Get groups route error:', error);
    res.status(error.status || 500).json({
      error: error.message,
      code: error.code
    });
  }
});

// ============================================
// GET CURRENT USER INFO
// ============================================
router.get('/auth/me', authenticateCognito, async (req, res) => {
  try {
    res.json({
      success: true,
      user: req.user,
      assessment2Demo: {
        authentication: 'Cognito ID Token validated',
        groups: req.user.groups,
        permissions: {
          canUpload: true,
          canTranscode: true,
          canDelete: req.user.groups.includes('admin'),
          canManageUsers: req.user.groups.includes('admin')
        }
      }
    });

  } catch (error) {
    console.error('Get user route error:', error);
    res.status(500).json({
      error: 'Failed to get user info',
      code: 'SERVER_ERROR'
    });
  }
});

// ============================================
// GET COGNITO CONFIGURATION (for frontend)
// ============================================
router.get('/auth/config', (req, res) => {
  try {
    const config = cognitoAuth.getAuthConfiguration();
    
    res.json({
      success: true,
      config: config,
      googleLoginUrl: `${config.hostedUIUrl}/oauth2/authorize?client_id=${config.clientId}&response_type=code&scope=email+openid+profile&redirect_uri=${encodeURIComponent('https://' + process.env.STUDENT_ID + '-mpeg-video.cab432.com/api/v1/auth/callback')}&identity_provider=Google`
    });

  } catch (error) {
    console.error('Get config route error:', error);
    res.status(500).json({
      error: 'Failed to get authentication configuration',
      code: 'SERVER_ERROR'
    });
  }
});

// ============================================
// MIDDLEWARE - COGNITO AUTHENTICATION
// ============================================
async function authenticateCognito(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        error: 'Access token required',
        code: 'NO_TOKEN'
      });
    }

    // Verify Cognito token
    const verified = await cognitoAuth.verifyToken(token);

    if (!verified.valid) {
      return res.status(403).json({
        error: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    // Attach user info to request
    req.user = verified.user;
    req.user.accessToken = token;

    console.log(`✅ Authenticated: ${req.user.username} (Groups: ${req.user.groups.join(', ') || 'none'})`);
    
    next();

  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(403).json({
      error: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
}

// ============================================
// MIDDLEWARE - REQUIRE ADMIN GROUP
// ============================================
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.groups.includes('admin')) {
    return res.status(403).json({
      error: 'Admin access required',
      code: 'ADMIN_REQUIRED',
      assessment2Demo: {
        additional_criterion: 'Cognito User Groups',
        permissionCheck: 'Admin group membership required'
      }
    });
  }
  
  next();
}

// ============================================
// MIDDLEWARE - REQUIRE PREMIUM GROUP
// ============================================
function requirePremium(req, res, next) {
  if (!req.user || (!req.user.groups.includes('premium') && !req.user.groups.includes('admin'))) {
    return res.status(403).json({
      error: 'Premium access required',
      code: 'PREMIUM_REQUIRED',
      assessment2Demo: {
        additional_criterion: 'Cognito User Groups',
        permissionCheck: 'Premium or Admin group membership required'
      }
    });
  }
  
  next();
}

// Export router and middleware
module.exports = {
  router,
  authenticateCognito,
  requireAdmin,
  requirePremium
};
