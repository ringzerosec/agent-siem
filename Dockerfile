FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY public ./public
COPY cypher ./cypher
EXPOSE 8080
CMD ["node", "src/server.js"]
