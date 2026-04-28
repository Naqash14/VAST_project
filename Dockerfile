FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc g++ clang git && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir semgrep angr atheris hypothesis

COPY . .

RUN mkdir -p app/uploads app/reports app/static/images app/static/uploads
RUN useradd -m -u 1000 vastuser
RUN chown -R vastuser:vastuser /app
USER vastuser

EXPOSE 5000

CMD ["python", "run.py"]

