FROM selenium/standalone-chromium:latest

COPY ./ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
USER root
RUN apt-get update && \
    apt-get install -y nginx && \
    apt-get clean
COPY ./nginx/default.conf /etc/nginx/conf.d/default.conf

WORKDIR /app
COPY dependents.sh /app
RUN bash ./dependents.sh
RUN mkdir -p /app/templates
COPY ./templates/* /app/templates
RUN mkdir -p /app/pics
COPY ./pics/* /app/pics
RUN mkdir -p /app/2fa
COPY ./flag/* /

COPY app.py .

EXPOSE 80 4444
CMD service nginx start & python3 app.py & bash /opt/bin/entry_point.sh 