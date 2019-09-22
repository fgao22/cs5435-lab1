FROM python:3.7-slim-buster

COPY app/requirements.txt /tmp/requirements.txt

RUN pip install -r /tmp/requirements.txt

EXPOSE 8080

VOLUME ["/code"]

WORKDIR /code

CMD ["python3", "-m", "app"]
