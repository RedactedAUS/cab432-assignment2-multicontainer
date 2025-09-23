require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');

const authRoutes = require('./src/routes/auth');
const imageRoutes = require('./src/routes/images');

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// API health check
app.get('/api', (_req, res) => {
  res.json({ ok: true, service: 'CAB432 Image API', version: '1.0.0' });
});

// API routes
app.use('/auth', authRoutes);
app.use('/images', imageRoutes);

// Serve the web UI on root path
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Image API listening on http://0.0.0.0:${PORT}`));