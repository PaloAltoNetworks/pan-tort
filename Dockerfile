
FROM python:3.6-alpine

LABEL description="Tort"
LABEL version="1.0"
LABEL maintainer="sp-solutions@paloaltonetworks.com"

ENV CNC_USERNAME=paloalto
ENV CNC_PASSWORD=tort

WORKDIR /app
ADD requirements.txt /app/requirements.txt
ADD cnc/requirements.txt /app/cnc/requirements.txt
COPY src /app/src
COPY cnc /app/cnc

RUN apk add --update --no-cache git curl openssh gcc musl-dev python3-dev libffi-dev openssl-dev && \
    pip install --upgrade pip && pip install --no-cache-dir --no-use-pep517 -r requirements.txt && \
    pip install --no-cache-dir --no-use-pep517 -r cnc/requirements.txt && \
    apk del --no-cache gcc && \
    if [ -f /app/cnc/db.sqlite3 ]; then rm /app/cnc/db.sqlite3; fi && \
    python /app/cnc/manage.py migrate && \
    python /app/cnc/manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_superuser('${CNC_USERNAME}', 'admin@example.com', '${CNC_PASSWORD}')" && \
    chmod +x /app/cnc/start_app.sh

EXPOSE 80
ENTRYPOINT ["/app/cnc/start_app.sh"]