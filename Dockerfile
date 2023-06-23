FROM python:3.10.12

RUN apt update -y && apt install awscli nginx -y
WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

COPY nginx.conf /etc/nginx/nginx.conf
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

EXPOSE 80
EXPOSE 8000
EXPOSE 8501

CMD service nginx start && /app/run.sh
