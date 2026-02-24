FROM python:3.11-slim

LABEL maintainer="sflow-generator"
LABEL description="sFlow v5 packet generator for testing network monitoring stacks"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sflow/ ./sflow/
COPY main.py .
COPY config.yaml .

RUN useradd -r -u 1001 -s /sbin/nologin sflow && \
    chown -R sflow:sflow /app

USER sflow

# Default config path (override with SFLOW_CONFIG or mount a custom config.yaml)
ENV SFLOW_CONFIG=/app/config.yaml


HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python main.py --config $SFLOW_CONFIG --validate || exit 1

ENTRYPOINT ["python", "main.py"]
CMD ["--config", "/app/config.yaml"]
