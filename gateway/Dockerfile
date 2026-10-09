FROM node:22-alpine
WORKDIR /app
COPY gateway/package.json ./
RUN npm install --omit=dev
COPY gateway/src ./src
COPY gateway/scripts ./scripts
COPY gateway/public ./public

COPY openfga/model.json ./model.json
USER node
EXPOSE 4000
CMD ["node", "src/index.js"]
