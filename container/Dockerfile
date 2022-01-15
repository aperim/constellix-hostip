FROM python:3.8-alpine

ADD src/constellix/* /usr/src/app/
ADD src/requirements.txt /usr/src/app

RUN pip3 install --user -r /usr/src/app/requirements.txt

ENTRYPOINT ["/usr/src/app/host.py"]
CMD ["--help"]
