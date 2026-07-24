FROM nginx:1.25.2 AS web
FROM node:20
FROM debian:bookworm-slim
FROM alpine@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
RUN apt-get update && apt-get install -y curl=7.88.1-10+deb12u5 git
RUN apk add --no-cache openssl=3.1.4-r5
