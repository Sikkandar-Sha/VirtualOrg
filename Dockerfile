FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY world/ world/
COPY twins/ twins/
COPY control_center/ control_center/
COPY scripts/ scripts/
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "twins.app:app", "--host", "0.0.0.0", "--port", "8080"]
