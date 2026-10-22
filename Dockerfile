FROM nginx:1.27-alpine

# Static site. Build a specific edition first:
#   python3 scripts/build-edition.py --edition lan --out build/lan
#   docker build -t emsign-trust-check:lan build/lan
COPY public/ /usr/share/nginx/html/

# Self-check endpoint used by the LAN page to prove that the client browser is
# actually enforcing certificate validation (self-signed leaf, nothing else).
COPY canary/ /etc/nginx/canary/
COPY canary.conf /etc/nginx/conf.d/canary.conf

# Lightweight healthcheck: verify the main page is served.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1

EXPOSE 80 8443
