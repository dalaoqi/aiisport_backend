# 建置階段
FROM golang:1.23-alpine AS builder

# 安裝 ffmpeg
RUN apk update && apk add --no-cache ffmpeg

# 設定工作目錄
WORKDIR /app

# 快取依賴
COPY go.mod go.sum ./
RUN go mod download

# 複製程式碼
COPY . .

# 編譯應用程式
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -ldflags="-s -w" -o main .

# 部署階段 (使用 Alpine)
FROM alpine:latest

# 安裝 ffmpeg
RUN apk update && apk add --no-cache ffmpeg

# 工作目錄
WORKDIR /root/

# 複製執行檔
COPY --from=builder /app/main .

# 暴露埠號 (根據應用程式設定)
EXPOSE 8080

# 執行應用程式
CMD ["./main"]
