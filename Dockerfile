FROM python:3.10.12

RUN apt update -y && apt install awscli nginx -y
WORKDIR /app

COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["python3", "app.py"]