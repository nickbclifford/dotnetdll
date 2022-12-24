# syntax=docker/dockerfile:1

# TODO: optimize for size, this Docker image is absolutely enormous (5.3GB)
# most of our CI time is being spent on just downloading this

# Includes dependencies for building the local runtime from scratch
FROM mcr.microsoft.com/dotnet-buildtools/prereqs:centos-7

# Download/extract runtime
WORKDIR /
RUN wget -nv https://github.com/dotnet/runtime/archive/refs/tags/v7.0.1.tar.gz
RUN tar xzf v7.0.1.tar.gz

# Build runtime
WORKDIR /runtime-7.0.1
RUN ./build.sh clr+libs -rc debug
ENV RUNTIME_ARTIFACTS=/runtime-7.0.1/artifacts

# Install production runtime + SDK
RUN rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm
RUN yum -y install dotnet-sdk-7.0 dotnet-runtime-7.0
ENV DOTNET_SDK=dotnet

# Install Rust
ENV CARGO_HOME=/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

WORKDIR /dotnetdll
CMD ["/cargo/bin/cargo", "test"]
