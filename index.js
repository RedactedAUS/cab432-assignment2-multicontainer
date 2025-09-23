// index.js
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegInstaller = require('@ffmpeg-installer/ffmpeg');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const axios = require('axios');

// Configure FFmpeg
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(limiter);

// Ensure directories exist
const ensureDir = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
};

ensureDir('./uploads');
ensureDir('./processed');
ensureDir('./data');

// Database setup
const db = new sqlite3.Database('./data/app.db');

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Videos table
  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    original_filename TEXT,
    filename TEXT,
    file_path TEXT,
    file_size INTEGER,
    mime_type TEXT,
    duration REAL,
    width INTEGER,
    height INTEGER,
    codec TEXT,
    bitrate INTEGER,
    status TEXT DEFAULT 'uploaded',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Processing jobs table
  db.run(`CREATE TABLE IF NOT EXISTS processing_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER,
    user_id INTEGER,
    job_type TEXT,
    status TEXT DEFAULT 'pending',
    input_path TEXT,
    output_path TEXT,
    parameters TEXT,
    progress INTEGER DEFAULT 0,
    started_at DATETIME,
    completed_at DATETIME,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(video_id) REFERENCES videos(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Video analytics table
  db.run(`CREATE TABLE IF NOT EXISTS video_analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER,
    analysis_type TEXT,
    results TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(video_id) REFERENCES videos(id)
  )`);

  // Insert default users if they don't exist
  const users = [
    { username: 'admin', password: 'admin123', email: 'admin@example.com', role: 'admin' },
    { username: 'user1', password: 'password123', email: 'user1@example.com', role: 'user' },
    { username: 'user2', password: 'password456', email: 'user2@example.com', role: 'user' }
  ];

  users.forEach(user => {
    const hashedPassword = bcrypt.hashSync(user.password, 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`,
      [user.username, hashedPassword, user.email, user.role]);
  });
});

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 500 * 1024 * 1024 // 500MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['video/mp4', 'video/avi', 'video/mov', 'video/mkv', 'video/wmv', 'video/flv'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only video files are allowed'));
    }
  }
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ROUTES

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    uptime: process.uptime()
  });
});

// Authentication endpoints - FIXED
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
      if (err) {
        console.error('Database error during login:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user) {
        console.log('User not found:', username);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      if (!bcrypt.compareSync(password, user.password)) {
        console.log('Invalid password for user:', username);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          role: user.role 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      console.log('Login successful for:', username, 'Role:', user.role);

      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get('SELECT id, username, email, role, created_at FROM users WHERE id = ?', 
    [req.user.id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(user);
  });
});

// ADMIN MANAGEMENT ENDPOINTS

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  db.all(`SELECT u.id, u.username, u.email, u.role, u.created_at,
          COUNT(v.id) as video_count,
          COUNT(j.id) as job_count,
          COALESCE(SUM(v.file_size), 0) as total_size
          FROM users u
          LEFT JOIN videos v ON u.id = v.user_id
          LEFT JOIN processing_jobs j ON u.id = j.user_id
          GROUP BY u.id
          ORDER BY u.created_at DESC`, (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ users });
  });
});

// Get all videos (admin only)
app.get('/api/admin/videos', authenticateToken, requireAdmin, (req, res) => {
  const query = `
    SELECT v.*, u.username, 
           COUNT(j.id) as job_count,
           MAX(j.created_at) as last_job_date
    FROM videos v
    JOIN users u ON v.user_id = u.id
    LEFT JOIN processing_jobs j ON v.id = j.video_id
    GROUP BY v.id
    ORDER BY v.created_at DESC
  `;

  db.all(query, (err, videos) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ videos });
  });
});

// Delete user and all their data (admin only)
app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, (req, res) => {
  const userId = req.params.userId;
  
  if (userId == req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own admin account' });
  }

  // Get user's videos to delete files
  db.all('SELECT file_path FROM videos WHERE user_id = ?', [userId], (err, videos) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // Delete video files from disk
    let deletedFiles = 0;
    videos.forEach(video => {
      try {
        if (fs.existsSync(video.file_path)) {
          fs.unlinkSync(video.file_path);
          deletedFiles++;
          console.log(`Deleted file: ${video.file_path}`);
        }
      } catch (error) {
        console.error(`Error deleting file ${video.file_path}:`, error);
      }
    });

    // Get processed files to delete
    db.all('SELECT output_path FROM processing_jobs WHERE user_id = ? AND output_path IS NOT NULL', [userId], (err, jobs) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      // Delete processed files
      jobs.forEach(job => {
        try {
          if (job.output_path && fs.existsSync(job.output_path)) {
            fs.unlinkSync(job.output_path);
            deletedFiles++;
            console.log(`Deleted processed file: ${job.output_path}`);
          }
        } catch (error) {
          console.error(`Error deleting processed file ${job.output_path}:`, error);
        }
      });

      // Delete database records in order (foreign key constraints)
      db.serialize(() => {
        db.run('DELETE FROM video_analytics WHERE video_id IN (SELECT id FROM videos WHERE user_id = ?)', [userId]);
        db.run('DELETE FROM processing_jobs WHERE user_id = ?', [userId]);
        db.run('DELETE FROM videos WHERE user_id = ?', [userId]);
        db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to delete user' });
          }
          
          if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
          }

          res.json({ 
            message: 'User and all associated data deleted successfully',
            deletedFiles: deletedFiles
          });
        });
      });
    });
  });
});

// Delete specific video and associated data (admin only)
app.delete('/api/admin/videos/:videoId', authenticateToken, requireAdmin, (req, res) => {
  const videoId = req.params.videoId;

  // Get video info first
  db.get('SELECT * FROM videos WHERE id = ?', [videoId], (err, video) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    // Get associated processing jobs
    db.all('SELECT output_path FROM processing_jobs WHERE video_id = ? AND output_path IS NOT NULL', [videoId], (err, jobs) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      let deletedFiles = 0;

      // Delete video file
      try {
        if (fs.existsSync(video.file_path)) {
          fs.unlinkSync(video.file_path);
          deletedFiles++;
          console.log(`Deleted video file: ${video.file_path}`);
        }
      } catch (error) {
        console.error(`Error deleting video file:`, error);
      }

      // Delete processed files
      jobs.forEach(job => {
        try {
          if (job.output_path && fs.existsSync(job.output_path)) {
            fs.unlinkSync(job.output_path);
            deletedFiles++;
            console.log(`Deleted processed file: ${job.output_path}`);
          }
        } catch (error) {
          console.error(`Error deleting processed file:`, error);
        }
      });

      // Delete database records
      db.serialize(() => {
        db.run('DELETE FROM video_analytics WHERE video_id = ?', [videoId]);
        db.run('DELETE FROM processing_jobs WHERE video_id = ?', [videoId]);
        db.run('DELETE FROM videos WHERE id = ?', [videoId], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to delete video' });
          }

          res.json({ 
            message: 'Video and all associated data deleted successfully',
            deletedFiles: deletedFiles
          });
        });
      });
    });
  });
});

// Video upload endpoint
app.post('/api/videos/upload', authenticateToken, upload.single('video'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No video file provided' });
    }

    const filePath = req.file.path;
    
    // Get video metadata using FFmpeg
    ffmpeg.ffprobe(filePath, (err, metadata) => {
      if (err) {
        console.error('FFprobe error:', err);
        return res.status(400).json({ error: 'Invalid video file' });
      }

      const videoStream = metadata.streams.find(stream => stream.codec_type === 'video');
      const format = metadata.format;

      const videoData = {
        user_id: req.user.id,
        original_filename: req.file.originalname,
        filename: req.file.filename,
        file_path: filePath,
        file_size: req.file.size,
        mime_type: req.file.mimetype,
        duration: format.duration,
        width: videoStream?.width || null,
        height: videoStream?.height || null,
        codec: videoStream?.codec_name || null,
        bitrate: format.bit_rate || null
      };

      db.run(`INSERT INTO videos (user_id, original_filename, filename, file_path, file_size, 
               mime_type, duration, width, height, codec, bitrate) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        Object.values(videoData),
        function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to save video metadata' });
          }

          res.status(201).json({
            message: 'Video uploaded successfully',
            video: {
              id: this.lastID,
              ...videoData
            }
          });
        }
      );
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get user's videos
app.get('/api/videos', authenticateToken, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  const status = req.query.status;
  const sortBy = req.query.sort || 'created_at';
  const sortOrder = req.query.order === 'asc' ? 'ASC' : 'DESC';

  let whereClause = 'WHERE user_id = ?';
  let params = [req.user.id];

  if (status) {
    whereClause += ' AND status = ?';
    params.push(status);
  }

  const query = `
    SELECT id, original_filename, filename, file_size, mime_type, duration, 
           width, height, codec, bitrate, status, created_at
    FROM videos 
    ${whereClause}
    ORDER BY ${sortBy} ${sortOrder}
    LIMIT ? OFFSET ?
  `;

  params.push(limit, offset);

  db.all(query, params, (err, videos) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    // Get total count for pagination
    db.get(`SELECT COUNT(*) as total FROM videos ${whereClause}`, 
      params.slice(0, -2), (err, countResult) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({
        videos,
        pagination: {
          page,
          limit,
          total: countResult.total,
          pages: Math.ceil(countResult.total / limit)
        }
      });
    });
  });
});

// Video transcoding (MAIN CPU INTENSIVE TASK)
app.post('/api/videos/:id/transcode', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;
    const { format = 'mp4', quality = 'medium', resolution } = req.body;

    // Verify video ownership or admin access
    const whereClause = req.user.role === 'admin' ? 'WHERE id = ?' : 'WHERE id = ? AND user_id = ?';
    const params = req.user.role === 'admin' ? [videoId] : [videoId, req.user.id];

    db.get(`SELECT * FROM videos ${whereClause}`, params, (err, video) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!video) {
        return res.status(404).json({ error: 'Video not found' });
      }

      const outputFileName = `transcoded_${Date.now()}_${video.filename.split('.')[0]}.${format}`;
      const outputPath = path.join('./processed', outputFileName);

      // Create processing job
      const jobData = {
        video_id: videoId,
        user_id: req.user.id,
        job_type: 'transcode',
        input_path: video.file_path,
        output_path: outputPath,
        parameters: JSON.stringify({ format, quality, resolution })
      };

      db.run(`INSERT INTO processing_jobs (video_id, user_id, job_type, input_path, 
               output_path, parameters, started_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
        Object.values(jobData),
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to create processing job' });
          }

          const jobId = this.lastID;

          // Start CPU-intensive transcoding process
          const command = ffmpeg(video.file_path)
            .format(format)
            .output(outputPath);

          // Configure quality settings (CPU intensive)
          switch (quality) {
            case 'high':
              command.videoBitrate('2000k').audioCodec('aac').audioBitrate('128k');
              break;
            case 'medium':
              command.videoBitrate('1000k').audioCodec('aac').audioBitrate('96k');
              break;
            case 'low':
              command.videoBitrate('500k').audioCodec('aac').audioBitrate('64k');
              break;
          }

          if (resolution) {
            command.size(resolution);
          }

          // Add CPU-intensive video filters
          command.videoFilters([
            'hqdn3d=2:1:2:3',
            'unsharp=5:5:1.0:5:5:0.0',
            'eq=contrast=1.1:brightness=0.05'
          ]);

          command
            .on('start', () => {
              console.log(`Started transcoding job ${jobId}`);
              db.run('UPDATE processing_jobs SET status = ? WHERE id = ?', 
                ['processing', jobId]);
            })
            .on('progress', (progress) => {
              const progressPercent = Math.round(progress.percent || 0);
              db.run('UPDATE processing_jobs SET progress = ? WHERE id = ?', 
                [progressPercent, jobId]);
            })
            .on('end', () => {
              db.run(`UPDATE processing_jobs SET status = ?, completed_at = datetime('now'), 
                       progress = 100 WHERE id = ?`, ['completed', jobId]);
              console.log(`Completed transcoding job ${jobId}`);
            })
            .on('error', (err) => {
              console.error(`Transcoding error for job ${jobId}:`, err);
              db.run(`UPDATE processing_jobs SET status = ?, error_message = ? WHERE id = ?`,
                ['failed', err.message, jobId]);
            })
            .run();

          res.status(202).json({
            message: 'Transcoding job started',
            jobId: jobId,
            status: 'processing'
          });
        }
      );
    });
  } catch (error) {
    console.error('Transcoding error:', error);
    res.status(500).json({ error: 'Failed to start transcoding' });
  }
});

// ENHANCED Download processed video with proper headers
app.get('/api/videos/:id/download/:jobId', authenticateToken, (req, res) => {
  const { id: videoId, jobId } = req.params;

  // Allow admin to download any file, users can only download their own
  const whereClause = req.user.role === 'admin' ? 
    'WHERE j.id = ? AND j.video_id = ? AND j.status = "completed"' :
    'WHERE j.id = ? AND j.video_id = ? AND j.user_id = ? AND j.status = "completed"';
  
  const params = req.user.role === 'admin' ? 
    [jobId, videoId] : 
    [jobId, videoId, req.user.id];

  const query = `
    SELECT j.*, v.original_filename 
    FROM processing_jobs j
    JOIN videos v ON j.video_id = v.id
    ${whereClause}
  `;

  db.get(query, params, (err, job) => {
    if (err) {
      console.error('Database error during download:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!job) {
      return res.status(404).json({ error: 'Processed video not found or access denied' });
    }

    if (!job.output_path) {
      return res.status(404).json({ error: 'No output file path recorded' });
    }

    const fullPath = path.resolve(job.output_path);
    
    if (!fs.existsSync(fullPath)) {
      console.error('File not found:', fullPath);
      return res.status(404).json({ error: 'File not found on disk' });
    }

    try {
      const stats = fs.statSync(fullPath);
      const originalName = path.parse(job.original_filename).name;
      const fileExt = path.extname(job.output_path);
      const downloadName = `${originalName}_transcoded${fileExt}`;

      console.log(`Starting download: ${downloadName} (${stats.size} bytes)`);

      // Set proper headers for download
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
      res.setHeader('Content-Length', stats.size);
      res.setHeader('Cache-Control', 'no-cache');

      // Stream the file
      const fileStream = fs.createReadStream(fullPath);
      
      fileStream.on('error', (streamErr) => {
        console.error('Stream error:', streamErr);
        if (!res.headersSent) {
          res.status(500).json({ error: 'File streaming error' });
        }
      });

      fileStream.on('end', () => {
        console.log('Download completed successfully');
      });

      fileStream.pipe(res);

    } catch (statErr) {
      console.error('Error reading file stats:', statErr);
      res.status(500).json({ error: 'File access error' });
    }
  });
});

// Get processing jobs
app.get('/api/jobs', authenticateToken, (req, res) => {
  const whereClause = req.user.role === 'admin' ? 
    '' : 'WHERE j.user_id = ?';
  
  const params = req.user.role === 'admin' ? [] : [req.user.id];

  const query = `
    SELECT j.*, v.original_filename, u.username
    FROM processing_jobs j
    LEFT JOIN videos v ON j.video_id = v.id
    LEFT JOIN users u ON j.user_id = u.id
    ${whereClause}
    ORDER BY j.created_at DESC
    LIMIT 50
  `;

  db.all(query, params, (err, jobs) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ jobs });
  });
});

// IMPROVED 5-minute dual-core CPU load test
app.post('/api/load-test', authenticateToken, requireAdmin, (req, res) => {
  const duration = 300; // 5 minutes in seconds
  const { cores = 2 } = req.body; // Allow specifying core count
  
  console.log(`Starting ${duration}s CPU load test on ${cores} cores`);
  
  const startTime = Date.now();
  const workers = [];
  
  // Create worker function for intense CPU load
  const cpuWorker = (workerId) => {
    return new Promise((resolve) => {
      const workerStart = Date.now();
      let iterations = 0;
      
      const intensiveWork = () => {
        const batchStart = Date.now();
        
        // Perform various CPU-intensive operations
        while (Date.now() - batchStart < 100) { // 100ms batches
          // Mathematical operations
          for (let i = 0; i < 100000; i++) {
            Math.sqrt(Math.random() * 1000000);
            Math.sin(Math.random() * Math.PI * 2);
            Math.cos(Math.random() * Math.PI * 2);
            Math.pow(Math.random() * 100, 3);
            Math.log(Math.random() * 1000 + 1);
            iterations++;
          }
          
          // Array operations
          const arr = Array.from({length: 1000}, () => Math.random());
          arr.sort();
          arr.reverse();
          
          // String operations
          let str = '';
          for (let j = 0; j < 100; j++) {
            str += Math.random().toString(36);
          }
          str.split('').reverse().join('');
        }
        
        // Continue if we haven't reached duration
        if (Date.now() - workerStart < duration * 1000) {
          setImmediate(intensiveWork);
        } else {
          resolve({
            workerId,
            iterations,
            duration: Date.now() - workerStart
          });
        }
      };
      
      intensiveWork();
    });
  };
  
  // Start workers for each core
  for (let i = 0; i < cores; i++) {
    workers.push(cpuWorker(i + 1));
  }
  
  // Don't wait for completion, return immediately
  res.json({
    message: `CPU load test started - running for ${duration} seconds on ${cores} cores`,
    duration: duration,
    cores: cores,
    started_at: new Date().toISOString(),
    estimated_completion: new Date(Date.now() + duration * 1000).toISOString()
  });
  
  // Log progress and results asynchronously
  Promise.all(workers).then(results => {
    const totalIterations = results.reduce((sum, result) => sum + result.iterations, 0);
    const actualDuration = (Date.now() - startTime) / 1000;
    
    console.log(`CPU load test completed:`, {
      actual_duration: actualDuration,
      total_iterations: totalIterations,
      average_iterations_per_second: Math.round(totalIterations / actualDuration),
      workers: results
    });
  });
});

// Enhanced analytics with admin/user separation
app.get('/api/analytics', authenticateToken, (req, res) => {
  if (req.user.role === 'admin') {
    // Admin gets system-wide analytics
    const queries = [
      'SELECT COUNT(*) as total_users FROM users WHERE role = "user"',
      'SELECT COUNT(*) as total_videos FROM videos',
      'SELECT COUNT(*) as total_jobs FROM processing_jobs',
      'SELECT COUNT(*) as completed_jobs FROM processing_jobs WHERE status = "completed"',
      'SELECT COUNT(*) as failed_jobs FROM processing_jobs WHERE status = "failed"',
      'SELECT COUNT(*) as active_jobs FROM processing_jobs WHERE status = "processing"',
      'SELECT SUM(file_size) as total_size FROM videos',
      'SELECT AVG(file_size) as avg_size FROM videos'
    ];

    Promise.all(queries.map(query => new Promise((resolve, reject) => {
      db.get(query, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    }))).then(results => {
      const [users, videos, jobs, completed, failed, active, totalSize, avgSize] = results;
      
      res.json({
        system_stats: {
          total_users: users.total_users || 0,
          total_videos: videos.total_videos || 0,
          total_jobs: jobs.total_jobs || 0,
          completed_jobs: completed.completed_jobs || 0,
          failed_jobs: failed.failed_jobs || 0,
          active_jobs: active.active_jobs || 0,
          success_rate: jobs.total_jobs > 0 ? 
            ((completed.completed_jobs / jobs.total_jobs) * 100).toFixed(1) + '%' : '0%',
          total_storage_mb: ((totalSize.total_size || 0) / (1024 * 1024)).toFixed(2),
          avg_file_size_mb: ((avgSize.avg_size || 0) / (1024 * 1024)).toFixed(2)
        }
      });
    }).catch(err => {
      console.error('Analytics query error:', err);
      res.status(500).json({ error: 'Database error' });
    });
  } else {
    // Regular user gets personal analytics
    const userId = req.user.id;
    
    db.get('SELECT COUNT(*) as total_videos FROM videos WHERE user_id = ?', [userId], (err, videoCount) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      
      db.get('SELECT COUNT(*) as total_jobs FROM processing_jobs WHERE user_id = ?', [userId], (err, jobCount) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        db.get('SELECT COUNT(*) as completed_jobs FROM processing_jobs WHERE user_id = ? AND status = "completed"', [userId], (err, completedCount) => {
          if (err) return res.status(500).json({ error: 'Database error' });
          
          db.get('SELECT SUM(file_size) as total_size FROM videos WHERE user_id = ?', [userId], (err, sizeResult) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            const successRate = jobCount.total_jobs > 0 ? 
              ((completedCount.completed_jobs / jobCount.total_jobs) * 100).toFixed(1) : '0';
            
            res.json({
              user_stats: {
                totalVideos: videoCount.total_videos || 0,
                totalJobs: jobCount.total_jobs || 0,
                successRate: successRate + '%',
                totalSize: ((sizeResult.total_size || 0) / (1024 * 1024)).toFixed(2)
              }
            });
          });
        });
      });
    });
  }
});

// System stats (for monitoring)
app.get('/api/system/stats', authenticateToken, requireAdmin, (req, res) => {
  const stats = {
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage(),
    platform: process.platform,
    nodeVersion: process.version
  };

  // Get database stats
  db.all(`
    SELECT 
      (SELECT COUNT(*) FROM users) as total_users,
      (SELECT COUNT(*) FROM videos) as total_videos,
      (SELECT COUNT(*) FROM processing_jobs WHERE status = 'processing') as active_jobs,
      (SELECT COUNT(*) FROM processing_jobs WHERE status = 'completed') as completed_jobs
  `, (err, dbStats) => {
    if (!err && dbStats.length > 0) {
      stats.database = dbStats[0];
    }
    
    res.json(stats);
  });
});

// External API integration (YouTube Data API example)
app.get('/api/videos/:id/recommendations', authenticateToken, async (req, res) => {
  try {
    const videoId = req.params.id;

    // Allow admin to access any video
    const whereClause = req.user.role === 'admin' ? 'WHERE id = ?' : 'WHERE id = ? AND user_id = ?';
    const params = req.user.role === 'admin' ? [videoId] : [videoId, req.user.id];

    db.get(`SELECT * FROM videos ${whereClause}`, params, async (err, video) => {
      if (err || !video) {
        return res.status(404).json({ error: 'Video not found' });
      }

      try {
        // Mock external API call
        const mockRecommendations = [
          {
            title: "Similar Video Processing Tutorial",
            thumbnail: "https://via.placeholder.com/320x180",
            duration: "5:30",
            views: "12,345"
          },
          {
            title: "Advanced MPEG Encoding Techniques",
            thumbnail: "https://via.placeholder.com/320x180", 
            duration: "8:45",
            views: "23,456"
          },
          {
            title: "Video Optimization Best Practices",
            thumbnail: "https://via.placeholder.com/320x180",
            duration: "6:20",
            views: "34,567"
          }
        ];

        res.json({
          video: video.original_filename,
          recommendations: mockRecommendations
        });
      } catch (apiError) {
        res.status(500).json({ error: 'Failed to fetch recommendations' });
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    }
    process.exit(0);
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MPEG Video Processing API running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🎬 FFmpeg path: ${ffmpegInstaller.path}`);
});