# TimesFM forecasting sidecar.
#
# Kept separate from the investigation runtime so torch and the HuggingFace
# stack never enter that image's dependency set or SBOM.
#
# Pinned to TimesFM 2.5, which is Apache-2.0. The 3.0 weights are licensed
# for non-commercial use only and are refused by the service.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Weights are staged into the image or a mount ahead of time; the model
    # loader must never reach the network at request time.
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    NETWORK_DORK_TIMESFM_CHECKPOINT=/models/timesfm-2.5-200m \
    NETWORK_DORK_TIMESFM_HOST=0.0.0.0 \
    NETWORK_DORK_TIMESFM_PORT=11435

RUN useradd --create-home --uid 10001 timesfm

# CPU-only torch: this is a 200M-parameter model, and pulling the CUDA wheels
# would add gigabytes for no benefit on a typical sensor host.
RUN pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        "torch==2.5.1" \
    # The package version is not the model version: there is no timesfm 2.5.0
# on PyPI. 2.0.2 is the release that ships TimesFM_2p5_200M_torch.
    && pip install --no-cache-dir "timesfm[torch]==2.0.2"

COPY app.py /opt/timesfm/app.py
RUN mkdir -p /models && chown -R timesfm:timesfm /models /opt/timesfm

USER timesfm
EXPOSE 11435
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:11435/health', timeout=4).status==200 else 1)"
CMD ["python", "/opt/timesfm/app.py"]
