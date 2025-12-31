FROM node:20-alpine

WORKDIR /app

# Install tools for command injection demo
RUN apk add --no-cache curl wget nmap iputils

COPY package*.json ./

RUN npm install

COPY . . 

RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start:prod"]
