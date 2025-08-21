FROM node:23-alpine AS builder
WORKDIR /app

COPY package.json pnpm-lock.yaml* ./

RUN npm install -g pnpm
RUN pnpm install

COPY . .
RUN pnpm run build

FROM python:3.10-slim
WORKDIR /app

COPY config.json .

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y curl
COPY src/server/ ./src/server/
COPY --from=builder /app/dist ./dist

EXPOSE 8000

CMD ["python","-m","src.server.run"] 