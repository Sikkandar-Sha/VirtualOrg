FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY world/ world/
COPY twins/ twins/
COPY control_center/ control_center/
COPY config/ config/
COPY scripts/ scripts/
ENV PYTHONUNBUFFERED=1
# Nothing here needs root: these processes read Postgres and serve HTTP. The host
# mounts are read-only, so this is the remaining half of that boundary.
# chmod normalises what COPY inherited from the builder's umask, so the image is
# the same whatever mode a contributor's checkout happens to carry.
RUN useradd -r -u 10001 vo && chmod -R a+rX /app
USER vo
CMD ["uvicorn", "twins.app:app", "--host", "0.0.0.0", "--port", "8080"]
