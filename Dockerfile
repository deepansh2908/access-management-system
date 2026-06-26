# Optional. One image for all services; the compose `command` selects which to run.
# Nothing depends on Docker — `npm run start` / `npm run demo` also run everything.
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
EXPOSE 4000 4001 4002 4003 4004
CMD ["npm", "run", "start"]
