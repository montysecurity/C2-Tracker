FROM python:3.11-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-c2-tracker
WORKDIR /opt/opencti-c2-tracker

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
RUN pip install --upgrade pip
RUN pip install requests pycti

ENTRYPOINT [ "python", "connector.py" ]