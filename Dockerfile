# Multi-stage build for NINA Healthcare Assistant

# Build stage
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build
RUN npm run build:server

# Production stage
FROM node:18-alpine AS production

# Install production dependencies
RUN apk add --no-cache curl

# Create app user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nina -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder --chown=nina:nodejs /app/dist ./dist
COPY --from=builder --chown=nina:nodejs /app/public ./public
COPY --from=builder --chown=nina:nodejs /app/server ./server
COPY --from=builder --chown=nina:nodejs /app/shared ./shared

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads && \
    chown -R nina:nodejs /app/logs /app/uploads

# Switch to non-root user
USER nina

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3001/api/health || exit 1

# Start the application
CMD ["npm", "start"]