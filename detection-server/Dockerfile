FROM python:3.11.5

WORKDIR /app
ADD . /app
RUN pip install -r requirements.txt

ENV PORT=4000
EXPOSE 4000
CMD ["python", "server.py"]
