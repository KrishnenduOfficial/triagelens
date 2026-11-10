FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir --only-binary=:all: -r requirements-postgres.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin triagelens
COPY alembic.ini ./
COPY migrations ./migrations
COPY src ./src
COPY rules ./rules
COPY data/attack/enterprise-17.1.json ./data/attack/enterprise-17.1.json
COPY deploy/start.py ./deploy/start.py
USER 10001:10001
CMD ["python", "deploy/start.py", "api"]
