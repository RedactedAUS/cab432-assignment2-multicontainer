#!/usr/bin/env node


const http = require('http');

const options = {
  hostname: 'localhost',
  port: process.env.PORT || 3000,
  path: '/api/health',
  method: 'GET',
  timeout: 3000
};

const healthCheck = http.request(options, (res) => {
  console.log(`Health check status: ${res.statusCode}`);
  
  if (res.statusCode === 200) {
    process.exit(0); // Success
  } else {
    process.exit(1); // Failure
  }
});

healthCheck.on('error', (err) => {
  console.error('Health check failed:', err.message);
  process.exit(1); // Failure
});

healthCheck.on('timeout', () => {
  console.error('Health check timed out');
  healthCheck.destroy();
  process.exit(1); // Failure
});

healthCheck.end();