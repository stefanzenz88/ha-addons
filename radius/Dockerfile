FROM python:3.12-alpine
RUN apk add --no-cache freeradius tzdata
COPY radius_app.py /radius_app.py
CMD ["python3", "-u", "/radius_app.py"]
