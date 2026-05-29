FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Create directories for graph persistence and SQLite database
RUN mkdir -p /app/snapshots /app/data

EXPOSE 5000

CMD ["python", "-m", "src.gui"]
