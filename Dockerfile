FROM python:3.11

COPY axltoolkit/ /app/axltoolkit
COPY perfmon_collector.py /app
COPY requirements.txt /app

WORKDIR /app

RUN apt-get -y update
RUN apt-get -y upgrade
RUN pip3 install -r requirements.txt

CMD ["python3", "perfmon_collector.py", "perfmon.yaml"]