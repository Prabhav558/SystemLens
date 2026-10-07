"""Minimal demo service: polls Postgres every few seconds and logs plain-text
lines to a shared volume so the host-side SystemLens agent can tail them
exactly like a normal application log file.
"""
import logging
import os
import sys
import time

import psycopg2

LOG_PATH = "/var/log/app/backend.log"
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:demo@db:5432/demo")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("backend")

while True:
    try:
        conn = psycopg2.connect(DATABASE_URL, connect_timeout=3)
        conn.close()
        log.info("db healthcheck ok")
    except psycopg2.OperationalError as e:
        log.error("db healthcheck failed: %s", e)
    time.sleep(4)
