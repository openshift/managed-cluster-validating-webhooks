FROM registry.access.redhat.com/ubi8/ubi

# Install python
RUN yum install python3 --nodocs --assumeyes

# Prep working directory
RUN mkdir -p /app
WORKDIR /app

# Copy requirements file and install dependencies
COPY src/requirements.txt ./
RUN pip3 install -r /app/requirements.txt --no-cache-dir

# Copy rest of application
COPY src/. .
ENV FLASK_APP=webhook
EXPOSE 5000

CMD ["gunicorn", "--config", "/app/gunicorn.py"]
