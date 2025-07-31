FROM python:3.12.10-bookworm

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -yqq socat
RUN pip install pycryptodome
ADD golden-ticket.py golden-ticket.py

CMD socat TCP-L:9999,fork,reuseaddr EXEC:"python golden-ticket.py"