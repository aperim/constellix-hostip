FROM python:3.5-alpine

ADD constellix/* /usr/src/app/
ADD requirements.txt /usr/src/app

RUN pip3 install --user -r /usr/src/app/requirements.txt

ENTRYPOINT ["/usr/src/app/host.py"]
CMD ["--help"]
