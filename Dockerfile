FROM --platform=linux/amd64 ubuntu:22.04

ARG TZ="Etc/UTC"

RUN DEBIAN_FRONTEND="noninteractive" apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get upgrade -y && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y apt-utils apt-transport-https software-properties-common readline-common curl vim wget gnupg gnupg2 gnupg-agent ca-certificates git unzip tini

RUN curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/intel-sgx.list

RUN DEBIAN_FRONTEND="noninteractive" apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y \
        libsgx-urts \
        libsgx-dcap-quote-verify \
        libsgx-dcap-default-qpl && \
    DEBIAN_FRONTEND="noninteractive" apt-get clean -y

ADD dockerfile.d/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
ADD target/release/dcap-test /opt/dcap-test

CMD ["/opt/dcap-test"]
