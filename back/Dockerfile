FROM python:3.12-slim

WORKDIR /opt/app

COPY requirements.txt /opt/app/
COPY app/ /opt/app/
COPY config/ /opt/app/config 

RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3"]
CMD ["main.py"]
EXPOSE 8080
