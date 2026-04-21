FROM python:3.11

# Running as root — CWE-250 / CIS Docker Benchmark 4.1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

# No USER directive; container runs as root.
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
