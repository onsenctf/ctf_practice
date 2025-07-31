FROM python:3.12.10-bookworm

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -yqq socat
RUN pip install pycryptodome
ADD 01-translator.py 01-translator.py

CMD socat TCP-L:9999,fork,reuseaddr EXEC:"python 01-translator.py"
