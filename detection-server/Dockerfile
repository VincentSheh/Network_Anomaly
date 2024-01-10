FROM python:3.11.5

WORKDIR /app
ADD . /app
RUN pip install -r requirements.txt

ENV PORT=3001
EXPOSE 3001
CMD ["python", "detector.py"]