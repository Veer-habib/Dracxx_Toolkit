FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY dracxx ./dracxx
RUN pip install --upgrade pip && pip install -e .
ENTRYPOINT ["dracxx-vuln"]
