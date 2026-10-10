FROM python:3.12-slim

WORKDIR /opt/auth

COPY requirements.txt /opt/auth
RUN pip3 install -r requirements.txt

COPY main.py /opt/auth
COPY auth_service/ /opt/auth/auth_service

ENTRYPOINT ["python3"]
CMD ["main.py"]
EXPOSE 8081