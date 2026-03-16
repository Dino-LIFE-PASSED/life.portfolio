FROM node:20-slim

# Required to compile better-sqlite3 (native module)
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Store the database outside the app folder so it survives redeployments
# (mount /data as a volume in Dokploy)
ENV DB_PATH=/data/portfolio.db

EXPOSE 3000
CMD ["node", "index.js"]
