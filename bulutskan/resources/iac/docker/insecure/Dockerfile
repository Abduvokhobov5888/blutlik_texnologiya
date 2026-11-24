# ATAYLAB XATO QILINGAN TEST FAYLI.
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD https://example.com/app.tar.gz /opt/app/
RUN curl -s https://example.com/install.sh | sh
ENV API_KEY="sk_test_1234567890abcdef"
EXPOSE 22
CMD ["/opt/app/start.sh"]
