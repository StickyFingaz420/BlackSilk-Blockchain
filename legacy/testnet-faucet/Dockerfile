# Use official Node.js runtime as base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    sqlite \
    python3 \
    make \
    g++ \
    git

# Copy package files
COPY package*.json ./
COPY tsconfig*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Create data directory
RUN mkdir -p /app/data

# Build the application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Set ownership of the app directory
RUN chown -R nextjs:nodejs /app
USER nextjs

# Expose port
EXPOSE 3003

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "
    const http = require('http');
    const options = {
      host: 'localhost',
      port: 3003,
      path: '/health',
      timeout: 2000,
    };
    const request = http.request(options, (res) => {
      console.log('STATUS: ' + res.statusCode);
      process.exit(res.statusCode === 200 ? 0 : 1);
    });
    request.on('error', function(err) {
      console.log('ERROR: ' + err.message);
      process.exit(1);
    });
    request.end();
  "

# Start the application
CMD ["npm", "start"]
