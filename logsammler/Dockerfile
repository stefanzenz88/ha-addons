FROM python:3.12-alpine
RUN apk add --no-cache tzdata && pip install --no-cache-dir aiohttp==3.11.18
COPY audit.py logsammler.py /
WORKDIR /
CMD ["python3", "-u", "/logsammler.py"]
