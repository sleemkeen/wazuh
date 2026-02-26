FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl openssh-client && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /srv/remediation

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import httpx; r = httpx.get('http://localhost:8000/health'); r.raise_for_status()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
