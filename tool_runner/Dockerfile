# Dagger-AI tool-runner — bundles best-of-breed pentest tools on Kali.
# Heavy first build (Kali base + Go tool builds + nuclei templates). Lab/authorized use only.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/go/bin:${PATH}" \
    PYTHONUNBUFFERED=1

# Core toolchain from Kali repos + Go to build ProjectDiscovery tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap sqlmap whatweb ffuf seclists dnsutils \
        golang-go git ca-certificates curl \
        python3 python3-pip gcc \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery httpx + nuclei (reliable, latest) via go install.
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && /root/go/bin/nuclei -update-templates || true

RUN pip3 install --no-cache-dir --break-system-packages \
        fastapi==0.115.6 "uvicorn[standard]==0.34.0" pydantic==2.10.4

WORKDIR /srv
COPY tools.py runner.py ./

EXPOSE 9020
CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "9020"]
