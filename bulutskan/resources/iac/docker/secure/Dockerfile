# XAVFSIZ SOZLANGAN TEST FAYLI.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY app/ /opt/app/
RUN useradd --create-home --uid 10001 appuser
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/opt/app/healthcheck.sh"]
CMD ["/opt/app/start.sh"]
