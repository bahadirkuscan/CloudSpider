FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Create snapshots directory for graph persistence
RUN mkdir -p /app/snapshots

EXPOSE 5000

CMD ["python", "-m", "src.gui"]
