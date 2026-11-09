FROM python:3.12-alpine
RUN apk add --no-cache tzdata
COPY logsammler.py /logsammler.py
CMD ["python3", "-u", "/logsammler.py"]
