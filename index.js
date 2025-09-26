// Complete updated index.js - Assessment 2 with Cognito Integration
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegInstaller = require('@ffmpeg-installer/ffmpeg');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const AWS = require('aws-sdk');
const multerS3 = require('multer-s3');
const { Pool } = require('pg');
const Cognito = require("@aws-sdk/client-cognito-identity-provider");
const crypto = require("crypto");
const jwksClient = require('jwks-rsa');
const util = require('util');

// Configure FFmpeg
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// Configure AWS
AWS.config.update({
  region: process.env.AWS_REGION || 'ap-southeast-2'
});

const s3 = new AWS.S3();

// Database Configuration (RDS PostgreSQL)
const pool = new Pool({
  host: process.env.RDS_HOSTNAME || 'localhost',
  port: process.env.RDS_PORT || 5432,
  user: process.env.RDS_USERNAME || 'postgres',
  password: process.env.RDS_PASSWORD || 'password',
  database: process.env.RDS_DB_NAME || 'mpegapi',
  ssl:false
});

// Cognito Configuration
const COGNITO_REGION = process.env.COGNITO_REGION || 'ap-southeast-2';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'ap-southeast-2_hqzxMJpG0';
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || '55p9dqrdmv3et2f64tsbtibmen';
const S3_BUCKET = process.env.S3_BUCKET_NAME || 'cab432-mpeg-videos';

// Cognito client
const cognitoClient = new Cognito.CognitoIdentityProviderClient({
  region: COGNITO_REGION
});

// JWKS client for verifying Cognito JWTs
const jwksUri = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}/.well-known/jwks.json`;
const client = jwksClient({
  jwksUri: jwksUri,
  cache: true,
  cacheMaxAge: 600000,
  rateLimit: true,
  jwksRequestsPerMinute: 10
});

// Helper functions for Cognito
function createSecretHash(clientId, clientSecret, username) {
  if (!clientSecret) return undefined;
  const hasher = crypto.createHmac('sha256', clientSecret);
  hasher.update(`${username}${clientId}`);
  return hasher.digest('base64');
}

const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err, null);
    } else {
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    }
  });
};

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// API VERSIONING
const API_VERSION = 'v1';
const API_BASE = `/api/${API_VERSION}`;

// Rate limiting
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message, code: 'RATE_LIMIT_EXCEEDED' },
  standardHeaders: true,
  legacyHeaders: false
});

const generalLimiter = createRateLimit(15 * 60 * 1000, 100, 'Too many requests');
const uploadLimiter = createRateLimit(15 * 60 * 1000, 10, 'Too many uploads');
const authLimiter = createRateLimit(15 * 60 * 1000, 5, 'Too many login attempts');

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Version', 'X-Request-ID'],
  exposedHeaders: ['X-Total-Count', 'X-Page-Count', 'Link']
}));

// Request tracking middleware
app.use((req, res, next) => {
  req.requestId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  req.startTime = Date.now();
  
  res.set({
    'X-API-Version': API_VERSION,
    'X-Request-ID': req.requestId,
    'X-RateLimit-Remaining': req.rateLimit?.remaining || 'unlimited'
  });
  
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - Request ID: ${req.requestId}`);
  next();
});

// Standard middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));
app.use(generalLimiter);

// Database Initialization
const initializeDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        cognito_sub VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        email_verified BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        login_count INTEGER DEFAULT 0
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        original_filename TEXT NOT NULL,
        s3_key TEXT NOT NULL,
        s3_bucket TEXT NOT NULL,
        file_size BIGINT,
        mime_type TEXT,
        duration REAL,
        width INTEGER,
        height INTEGER,
        codec TEXT,
        bitrate INTEGER,
        status TEXT DEFAULT 'uploaded',
        tags TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS processing_jobs (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        job_type TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        input_s3_key TEXT,
        output_s3_key TEXT,
        parameters JSONB,
        progress INTEGER DEFAULT 0,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        error_message TEXT,
        cpu_time REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
    process.exit(1);
  }
};

// S3 File Upload Configuration
const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: S3_BUCKET,
    key: function (req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      const key = `videos/${req.user?.id || 'anonymous'}/${uniqueSuffix}-${file.originalname}`;
      cb(null, key);
    },
    contentType: multerS3.AUTO_CONTENT_TYPE,
    metadata: function (req, file, cb) {
      cb(null, {
        fieldName: file.fieldname,
        originalName: file.originalname,
        uploadedBy: req.user?.id || 'anonymous'
      });
    }
  }),
  limits: { 
    fileSize: 500 * 1024 * 1024 // 500MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['video/mp4', 'video/avi', 'video/mov', 'video/mkv', 'video/wmv'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only video files allowed'));
    }
  }
});

// Authentication Middleware with Cognito JWT Verification
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      error: 'Access token required', 
      code: 'NO_AUTH',
      message: 'Please include Authorization: Bearer <idToken> header'
    });
  }

  try {
    // Verify the JWT using Cognito's public keys
    const verifiedToken = await new Promise((resolve, reject) => {
      jwt.verify(token, getKey, {
        algorithms: ['RS256'],
        issuer: `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`,
        audience: COGNITO_CLIENT_ID
      }, (err, decoded) => {
        if (err) reject(err);
        else resolve(decoded);
      });
    });

    // Check token use - must be 'id'
    if (verifiedToken.token_use !== 'id') {
      throw new Error('Token must be an ID token, not an access token');
    }

    // Extract user information
    const cognitoSub = verifiedToken.sub;
    const username = verifiedToken['cognito:username'] || verifiedToken.preferred_username;
    const email = verifiedToken.email;

    // Check if user exists in database
    let result = await pool.query(
      'SELECT * FROM users WHERE cognito_sub = $1',
      [cognitoSub]
    );
    
    let user;
    if (result.rows.length === 0) {
      // Create user in database
      const createResult = await pool.query(
        `INSERT INTO users (cognito_sub, username, email, email_verified, role) 
         VALUES ($1, $2, $3, $4, $5) 
         RETURNING *`,
        [cognitoSub, username, email, verifiedToken.email_verified || false, 'user']
      );
      user = createResult.rows[0];
    } else {
      user = result.rows[0];
      await pool.query(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE id = $1',
        [user.id]
      );
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ 
      error: 'Invalid or expired token', 
      code: 'INVALID_TOKEN',
      details: error.message
    });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Admin access required', 
      code: 'INSUFFICIENT_PRIVILEGES' 
    });
  }
  next();
};

// Helper Functions
const getPaginationData = (req) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 10), 100);
  const offset = (page - 1) * limit;
  return { page, limit, offset };
};

// HEALTH CHECK
app.get(`${API_BASE}/health`, async (req, res) => {
  try {
    await pool.query('SELECT 1');
    await s3.headBucket({ Bucket: S3_BUCKET }).promise();
    
    let cognitoStatus = 'configured';
    try {
      await axios.get(jwksUri, { timeout: 5000 });
      cognitoStatus = 'connected';
    } catch (error) {
      cognitoStatus = 'unreachable';
    }
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: API_VERSION,
      uptime: process.uptime(),
      services: {
        database: 'connected',
        s3: 'connected',
        cognito: cognitoStatus
      },
      cognito_config: {
        region: COGNITO_REGION,
        user_pool_id: COGNITO_USER_POOL_ID,
        client_id: COGNITO_CLIENT_ID,
        jwks_endpoint: jwksUri
      }
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// COGNITO AUTHENTICATION ENDPOINTS

// SIGNUP ENDPOINT
app.post(`${API_BASE}/auth/signup`, authLimiter, async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['username', 'password', 'email']
    });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      error: 'Password does not meet requirements',
      requirements: 'Min 8 chars, uppercase, lowercase, number, special char'
    });
  }

  try {
    const clientSecret = process.env.COGNITO_CLIENT_SECRET || '';
    const secretHash = createSecretHash(COGNITO_CLIENT_ID, clientSecret, username);

    const signUpParams = {
      ClientId: COGNITO_CLIENT_ID,
      Username: username,
      Password: password,
      UserAttributes: [
        { Name: "email", Value: email }
      ]
    };

    if (secretHash) {
      signUpParams.SecretHash = secretHash;
    }

    const command = new Cognito.SignUpCommand(signUpParams);
    const response = await cognitoClient.send(command);

    res.status(201).json({
      success: true,
      message: 'User created successfully. Check email for confirmation code.',
      username: username,
      userSub: response.UserSub,
      confirmationRequired: !response.UserConfirmed
    });

  } catch (error) {
    if (error.name === 'UsernameExistsException') {
      return res.status(409).json({ error: 'Username already exists' });
    } else if (error.name === 'InvalidPasswordException') {
      return res.status(400).json({ error: 'Password does not meet requirements' });
    }
    res.status(500).json({ error: 'Failed to create user', details: error.message });
  }
});

// CONFIRM SIGNUP ENDPOINT
app.post(`${API_BASE}/auth/confirm`, authLimiter, async (req, res) => {
  const { username, confirmationCode } = req.body;

  if (!username || !confirmationCode) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['username', 'confirmationCode']
    });
  }

  try {
    const clientSecret = process.env.COGNITO_CLIENT_SECRET || '';
    const secretHash = createSecretHash(COGNITO_CLIENT_ID, clientSecret, username);

    const confirmParams = {
      ClientId: COGNITO_CLIENT_ID,
      Username: username,
      ConfirmationCode: confirmationCode
    };

    if (secretHash) {
      confirmParams.SecretHash = secretHash;
    }

    const command = new Cognito.ConfirmSignUpCommand(confirmParams);
    await cognitoClient.send(command);

    res.json({
      success: true,
      message: 'Email confirmed successfully. You can now login.',
      username: username
    });

  } catch (error) {
    if (error.name === 'CodeMismatchException') {
      return res.status(400).json({ error: 'Invalid confirmation code' });
    } else if (error.name === 'ExpiredCodeException') {
      return res.status(400).json({ error: 'Confirmation code expired' });
    }
    res.status(500).json({ error: 'Failed to confirm user', details: error.message });
  }
});

// LOGIN ENDPOINT
app.post(`${API_BASE}/auth/login`, authLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const clientSecret = process.env.COGNITO_CLIENT_SECRET || '';
    const secretHash = createSecretHash(COGNITO_CLIENT_ID, clientSecret, username);

    const authParams = {
      USERNAME: username,
      PASSWORD: password
    };

    if (secretHash) {
      authParams.SECRET_HASH = secretHash;
    }

    const command = new Cognito.InitiateAuthCommand({
      AuthFlow: Cognito.AuthFlowType.USER_PASSWORD_AUTH,
      AuthParameters: authParams,
      ClientId: COGNITO_CLIENT_ID
    });

    const response = await cognitoClient.send(command);

    const idToken = response.AuthenticationResult.IdToken;
    const accessToken = response.AuthenticationResult.AccessToken;
    const refreshToken = response.AuthenticationResult.RefreshToken;

    // Verify user exists in database or create them
    const decodedIdToken = jwt.decode(idToken);
    const cognitoSub = decodedIdToken.sub;
    const email = decodedIdToken.email;

    let userResult = await pool.query(
      'SELECT * FROM users WHERE cognito_sub = $1',
      [cognitoSub]
    );

    if (userResult.rows.length === 0) {
      userResult = await pool.query(
        `INSERT INTO users (cognito_sub, username, email, email_verified, role) 
         VALUES ($1, $2, $3, $4, $5) 
         RETURNING *`,
        [cognitoSub, username, email, decodedIdToken.email_verified || false, 'user']
      );
    } else {
      await pool.query(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE cognito_sub = $1',
        [cognitoSub]
      );
    }

    const user = userResult.rows[0];

    res.json({
      success: true,
      message: 'Login successful',
      tokens: {
        idToken: idToken,
        accessToken: accessToken,
        refreshToken: refreshToken,
        expiresIn: response.AuthenticationResult.ExpiresIn
      },
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    if (error.name === 'NotAuthorizedException') {
      return res.status(401).json({ error: 'Invalid username or password' });
    } else if (error.name === 'UserNotConfirmedException') {
      return res.status(403).json({ error: 'User email not confirmed' });
    }
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
});

// RESEND CONFIRMATION CODE
app.post(`${API_BASE}/auth/resend-code`, authLimiter, async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }

  try {
    const clientSecret = process.env.COGNITO_CLIENT_SECRET || '';
    const secretHash = createSecretHash(COGNITO_CLIENT_ID, clientSecret, username);

    const resendParams = {
      ClientId: COGNITO_CLIENT_ID,
      Username: username
    };

    if (secretHash) {
      resendParams.SecretHash = secretHash;
    }

    const command = new Cognito.ResendConfirmationCodeCommand(resendParams);
    await cognitoClient.send(command);

    res.json({
      success: true,
      message: 'Confirmation code resent to your email'
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to resend code', details: error.message });
  }
});

// GET CURRENT USER
app.get(`${API_BASE}/auth/me`, authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      emailVerified: req.user.email_verified,
      lastLogin: req.user.last_login,
      loginCount: req.user.login_count
    },
    cognito_integration: 'server_side_verification'
  });
});

// VIDEO ENDPOINTS
app.get(`${API_BASE}/videos`, authenticateToken, async (req, res) => {
  try {
    const { page, limit, offset } = getPaginationData(req);
    
    let query = 'SELECT * FROM videos';
    let countQuery = 'SELECT COUNT(*) FROM videos';
    let params = [];
    
    if (req.user.role !== 'admin') {
      query += ' WHERE user_id = $1';
      countQuery += ' WHERE user_id = $1';
      params = [req.user.id];
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    
    const [videos, count] = await Promise.all([
      pool.query(query, [...params, limit, offset]),
      pool.query(countQuery, params)
    ]);
    
    const totalCount = parseInt(count.rows[0].count);
    const totalPages = Math.ceil(totalCount / limit);
    
    res.json({
      data: videos.rows,
      pagination: {
        current_page: page,
        per_page: limit,
        total_items: totalCount,
        total_pages: totalPages,
        has_next_page: page < totalPages,
        has_previous_page: page > 1
      },
      meta: {
        request_id: req.requestId,
        processing_time: `${Date.now() - req.startTime}ms`
      }
    });
    
  } catch (error) {
    console.error('Error fetching videos:', error);
    res.status(500).json({ 
      error: 'Failed to fetch videos', 
      code: 'DB_ERROR' 
    });
  }
});

app.post(`${API_BASE}/videos/upload`, authenticateToken, uploadLimiter, upload.single('video'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No video file provided', 
        code: 'NO_FILE' 
      });
    }

    const { tags, description } = req.body;
    const s3Key = req.file.key;
    const s3Location = req.file.location;

    const tempUrl = s3.getSignedUrl('getObject', {
      Bucket: S3_BUCKET,
      Key: s3Key,
      Expires: 3600
    });

    ffmpeg.ffprobe(tempUrl, async (err, metadata) => {
      if (err) {
        console.error('FFprobe error:', err);
        return res.status(400).json({ 
          error: 'Invalid video file', 
          code: 'INVALID_VIDEO' 
        });
      }

      const videoStream = metadata.streams.find(stream => stream.codec_type === 'video');
      const format = metadata.format;

      try {
        const result = await pool.query(
          `INSERT INTO videos (
            user_id, original_filename, s3_key, s3_bucket, file_size, 
            mime_type, duration, width, height, codec, bitrate, tags, description
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
          RETURNING *`,
          [
            req.user.id,
            req.file.originalname,
            s3Key,
            S3_BUCKET,
            req.file.size,
            req.file.mimetype,
            format.duration,
            videoStream?.width || null,
            videoStream?.height || null,
            videoStream?.codec_name || null,
            format.bit_rate || null,
            tags || '',
            description || ''
          ]
        );

        const video = result.rows[0];

        res.status(201).json({
          message: 'Video uploaded successfully to S3',
          video: {
            id: video.id,
            original_filename: video.original_filename,
            s3_key: video.s3_key,
            file_size: video.file_size,
            duration: video.duration,
            width: video.width,
            height: video.height,
            codec: video.codec
          },
          s3_location: s3Location
        });

      } catch (dbError) {
        console.error('Database error:', dbError);
        res.status(500).json({ 
          error: 'Failed to save video metadata', 
          code: 'DB_ERROR' 
        });
      }
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ 
      error: 'Upload failed', 
      code: 'UPLOAD_ERROR' 
    });
  }
});

// ANALYTICS ENDPOINT
app.get(`${API_BASE}/analytics`, authenticateToken, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      const stats = await pool.query(`
        SELECT 
          (SELECT COUNT(*) FROM videos) as total_videos,
          (SELECT COUNT(*) FROM processing_jobs) as total_jobs,
          (SELECT COUNT(*) FROM users) as total_users,
          (SELECT COUNT(*) FROM processing_jobs WHERE status = 'completed') as completed_jobs,
          (SELECT COALESCE(SUM(file_size), 0) FROM videos) as total_storage
      `);

      const result = stats.rows[0];
      
      res.json({
        system_stats: {
          total_videos: parseInt(result.total_videos) || 0,
          total_jobs: parseInt(result.total_jobs) || 0,
          total_users: parseInt(result.total_users) || 0,
          total_storage_mb: Math.round((result.total_storage || 0) / (1024 * 1024))
        }
      });
    } else {
      const stats = await pool.query(`
        SELECT 
          (SELECT COUNT(*) FROM videos WHERE user_id = $1) as user_videos,
          (SELECT COUNT(*) FROM processing_jobs WHERE user_id = $1) as user_jobs,
          (SELECT COALESCE(SUM(file_size), 0) FROM videos WHERE user_id = $1) as user_storage
      `, [req.user.id]);

      const result = stats.rows[0];
      
      res.json({
        user_stats: {
          totalVideos: parseInt(result.user_videos) || 0,
          totalJobs: parseInt(result.user_jobs) || 0,
          totalSize: Math.round((result.user_storage || 0) / (1024 * 1024)) + ' MB'
        }
      });
    }
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch analytics', 
      code: 'ANALYTICS_ERROR' 
    });
  }
});

// CPU LOAD TEST
app.post(`${API_BASE}/load-test`, authenticateToken, requireAdmin, (req, res) => {
  const { duration = 300, cores = 2 } = req.body;
  
  if (duration > 600) {
    return res.status(400).json({ 
      error: 'Duration cannot exceed 600 seconds' 
    });
  }

  const startTime = Date.now();
  const jobId = Date.now().toString(36);
  
  console.log(`Starting CPU load test: ${duration}s on ${cores} cores`);
  
  const cpuIntensiveWork = (workerId, duration) => {
    const startTime = Date.now();
    const endTime = startTime + (duration * 1000);
    let counter = 0;
    
    while (Date.now() < endTime) {
      for (let i = 0; i < 50000; i++) {
        let isPrime = true;
        const num = counter + i;
        if (num > 1) {
          for (let j = 2; j <= Math.sqrt(num); j++) {
            if (num % j === 0) {
              isPrime = false;
              break;
            }
          }
        }
        Math.sin(counter) * Math.cos(i);
      }
      counter += 50000;
    }
    return { workerId, operations: counter };
  };

  for (let i = 0; i < cores; i++) {
    setTimeout(() => {
      cpuIntensiveWork(i + 1, duration);
    }, i * 100);
  }

  res.json({
    message: 'CPU load test started',
    job_id: jobId,
    duration: duration,
    cores: cores,
    started_at: new Date().toISOString()
  });
});

// ERROR HANDLING MIDDLEWARE
app.use((error, req, res, next) => {
  console.error(`Error [${req.requestId}]:`, error);
  
  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: 'File too large',
      code: 'FILE_TOO_LARGE',
      max_size: '500MB'
    });
  }

  res.status(500).json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    request_id: req.requestId
  });
});

// 404 HANDLER
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    code: 'ENDPOINT_NOT_FOUND',
    path: req.originalUrl,
    method: req.method
  });
});

// GRACEFUL SHUTDOWN
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  try {
    await pool.end();
  } catch (error) {
    console.error('Error closing database:', error);
  }
  process.exit(0);
});

// START SERVER
const startServer = async () => {
  try {
    await initializeDatabase();
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`�� MPEG Video Processing API v${API_VERSION} running on port ${PORT}`);
      console.log(`�� Health Check: http://localhost:${PORT}${API_BASE}/health`);
      console.log(`�� Cognito Integration: ACTIVE`);
      console.log(`   - User Pool: ${COGNITO_USER_POOL_ID}`);
      console.log(`   - Client ID: ${COGNITO_CLIENT_ID}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
