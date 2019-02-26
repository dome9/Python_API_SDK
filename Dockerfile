FROM python:3.7

COPY . /root/dome9

RUN pip3 install -r /root/dome9/requirements.txt
