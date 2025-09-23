FROM node:18-alpine
WORKDIR /app

RUN apk add --no-cache \
    ffmpeg \
    python3 \
    make \
    g++ \
    sqlite

COPY package*.json ./
RUN npm ci --only=production

RUN mkdir -p uploads processed data public
COPY . .

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
RUN chown -R nodejs:nodejs /app
USER nodejs

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node healthcheck.js || exit 1
CMD ["npm", "start"]