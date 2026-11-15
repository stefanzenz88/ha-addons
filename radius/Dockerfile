FROM python:3.12-alpine
RUN apk add --no-cache freeradius freeradius-eap openssl tzdata
COPY radius_app.py /radius_app.py
CMD ["python3", "-u", "/radius_app.py"]
