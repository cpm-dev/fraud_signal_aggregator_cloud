FROM --platform=linux/amd64 rust:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-dev \
    python3-pip \
    build-essential \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages maturin

WORKDIR /workspace
COPY . .

RUN maturin build --release --target x86_64-unknown-linux-gnu -i python3 && \
    mkdir -p /artifacts/python/fraud_core && \
    unzip -o /workspace/target/wheels/fraud_core-0.1.0-cp313-cp313-manylinux_2_34_x86_64.whl -d /tmp/wheel && \
    cp /tmp/wheel/fraud_core/fraud_core.cpython-313-x86_64-linux-gnu.so /artifacts/python/fraud_core/ && \
    cp /tmp/wheel/fraud_core/__init__.py /artifacts/python/fraud_core/

CMD ["/bin/bash"]