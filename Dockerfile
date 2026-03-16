FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY pipeaudit/ ./pipeaudit/

RUN pip install --no-cache-dir .

ENTRYPOINT ["/bin/bash"]
