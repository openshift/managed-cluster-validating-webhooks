FROM python:3.7


ADD src /app
WORKDIR /app
RUN pip install -r /app/requirements.txt
ENV FLASK_APP=webhook
EXPOSE 5000

CMD ["gunicorn", "--config", "/app/gunicorn.py"]
