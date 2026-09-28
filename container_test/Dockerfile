FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography pycryptodome

WORKDIR /app

COPY crypto_test.py .

CMD ["python", "crypto_test.py"]
