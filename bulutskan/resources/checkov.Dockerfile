FROM python:3.12-slim
ARG CHECKOV_VERSION
RUN pip install --no-cache-dir "checkov==${CHECKOV_VERSION}"
ENTRYPOINT ["checkov"]
