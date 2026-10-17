FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && mkdir -p /app/data && chown node:node /app/data
COPY src ./src
COPY public ./public
COPY cypher ./cypher
USER node
EXPOSE 8080
CMD ["node", "src/server.js"]
