FROM python:3.13-slim

# NOTE: python:3.13-slim already ships tzdata + ca-certificates. tzdata matters:
# schedules run in settings.timezone (e.g. Europe/Berlin) — without the zoneinfo
# database they would silently shift to UTC.

# Non-root runtime user
RUN useradd --create-home --uid 1000 heim

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

# config/ is mounted read-only at runtime; /data holds all mutable state
# (heim.sqlite3, audit.jsonl, out/) because it is the working directory and
# every default path in settings.yaml is relative.
ENV HEIM_CONFIG=/app/config \
    PYTHONUNBUFFERED=1
RUN mkdir -p /data && chown heim:heim /data
VOLUME /data
WORKDIR /data
USER heim

ENTRYPOINT ["heim"]
CMD ["daemon"]
