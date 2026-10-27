FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY lantern ./lantern
RUN pip install --no-cache-dir .
VOLUME ["/data"]
EXPOSE 8068
CMD ["lantern", "web", "--host", "0.0.0.0", "--port", "8068", "--db", "/data/lantern.db"]
