FROM python:3.12-slim
WORKDIR /app
COPY app.py .
RUN pip install --no-cache-dir psycopg2-binary
CMD ["python", "app.py"]
