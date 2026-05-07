FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --default-timeout=1000 -r requirements.txt

COPY . .

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]