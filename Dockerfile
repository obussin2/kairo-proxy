FROM node:20-alpine

ENV NODE_ENV=production

WORKDIR /app

COPY package.json ./

# python3/make/g++ needed for native deps (wisp-js)
RUN apk add --upgrade --no-cache python3 make g++

# --ignore-scripts skips scramjet's "npx only-allow pnpm" preinstall check
RUN npm install --omit=dev --ignore-scripts

COPY . .

EXPOSE 3000
CMD ["node", "src/index.js"]
