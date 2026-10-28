# Dagger-AI tool-runner — bundles best-of-breed pentest tools on Kali.
# Heavy first build (Kali base + Go tool builds + nuclei templates). Lab/authorized use only.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/go/bin:${PATH}" \
    PYTHONUNBUFFERED=1

# Core toolchain from Kali repos + Go to build ProjectDiscovery tools.
# The small runner API (FastAPI + uvicorn + pydantic) is installed from Kali's
# own apt packages, which match the base image's Python. This avoids pip
# compiling pydantic-core from Rust source — Kali's Python has no prebuilt
# wheel for it, and the from-source build fails to link in this image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap sqlmap whatweb ffuf seclists dnsutils \
        nikto sslscan wafw00f commix \
        golang-go git ca-certificates curl \
        python3 python3-fastapi python3-uvicorn python3-pydantic \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery httpx + nuclei + subfinder + katana, and dalfox, via go install.
# Each is installed independently with retries so a transient network blip on one
# does not skip the rest (go module proxy DNS can flake during builds).
RUN for pkg in \
        github.com/projectdiscovery/httpx/cmd/httpx@latest \
        github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
        github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
        github.com/projectdiscovery/katana/cmd/katana@latest \
        github.com/hahwul/dalfox/v2@latest ; do \
        (go install "$pkg" || go install "$pkg" || go install "$pkg") \
            || echo "WARN: could not install $pkg" ; \
    done ; \
    (/root/go/bin/nuclei -update-templates || true)

WORKDIR /srv
COPY tools.py runner.py ./

EXPOSE 9020
# Launch via `python3 -m uvicorn` — Kali's apt uvicorn package doesn't put a
# `uvicorn` console script on PATH, but the module is importable.
CMD ["python3", "-m", "uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "9020"]
