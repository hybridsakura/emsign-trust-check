FROM nginx:1.27-alpine

# Static site only — no build step required.
COPY public/ /usr/share/nginx/html/

# Lightweight healthcheck: verify the main page is served.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1

EXPOSE 80
