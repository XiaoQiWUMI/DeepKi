# (●°u°●)​ 」 DeepKi Docker Image
# Xiao Qi in a container~ ♪───Ｏ（≧∇≦）Ｏ────♪

FROM python:3.12-slim

LABEL org.opencontainers.image.title="DeepKi"
LABEL org.opencontainers.image.description="The cutest black-box security scanner (●°u°●)​ 」"
LABEL org.opencontainers.image.version="1.0.0"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Create dirs
RUN mkdir -p /app/results

EXPOSE 5000

ENV DEEPKI_HOST=0.0.0.0
ENV DEEPKI_PORT=5000
ENV DEEPKI_DEBUG=false

CMD ["python", "-m", "app.main"]
