FROM python:3.11-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-c2-tracker
WORKDIR /opt/opencti-c2-tracker

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
RUN pip install requests==2.32.3
RUN pip install pycti==6.3.13

# Expose and run entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]