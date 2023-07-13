FROM python:3.10.11-alpine

ENV APP_HOME /app
WORKDIR /

COPY ./app *.py package.json requirements.txt /
RUN pip install -r requirements.txt

ENV PYTHONUNBUFFERED 1
ENTRYPOINT python main.py -c $APP_HOME/exporter_config.yaml