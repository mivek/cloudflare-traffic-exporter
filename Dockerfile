FROM python:3.13.7-alpine3.22
WORKDIR /app
COPY exporter.py /app/exporter.py
USER 65534:65534
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
CMD ["python", "-B", "/app/exporter.py"]
