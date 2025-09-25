# Assessment 2 Dockerfile - Stateless Cloud Application
FROM node:18-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    ffmpeg \
    python3 \
    make \
    g++

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm install --only=production

# Create directories (but don't rely on them for persistent storage)
RUN mkdir -p public temp

# Copy application files
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check using the API endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD node -e "const http = require('http'); const options = { hostname: 'localhost', port: 3000, path: '/api/v1/health', timeout: 5000 }; const req = http.request(options, (res) => process.exit(res.statusCode === 200 ? 0 : 1)); req.on('error', () => process.exit(1)); req.end();"

# Start the application
CMD ["npm", "start"]
