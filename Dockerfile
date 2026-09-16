# INTENTIONALLY VULNERABLE — teaching lab only.
FROM node:20-bookworm

WORKDIR /app

# VB-105/106: NODE_ENV left unset (development) on purpose -> verbose errors.
COPY package.json ./
RUN npm install --no-audit --no-fund

COPY . .

# VB-111: .git and backups are copied into the image on purpose (see .dockerignore absence).

EXPOSE 3000
CMD ["node", "src/server.js"]
