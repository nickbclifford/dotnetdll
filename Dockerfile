# syntax=docker/dockerfile:1

ENV RUNTIME_VERSION=9.0.1

# Includes dependencies for building the local runtime from scratch
FROM mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-22.04

# Environment variables
ENV RUNTIME_ARTIFACTS=/runtime-$RUNTIME_VERSION/artifacts DOTNET_SDK=dotnet CARGO_HOME=/cargo

# Download/extract runtime
WORKDIR /
RUN curl -OL https://github.com/dotnet/runtime/archive/refs/tags/v$RUNTIME_VERSION.tar.gz && \
    tar xzf v$RUNTIME_VERSION.tar.gz && \
    rm v$RUNTIME_VERSION.tar.gz

# Build runtime
WORKDIR /runtime-$RUNTIME_VERSION
RUN ./build.sh clr+libs -rc debug && \
    rm -rf /root/.local/share/NuGet /root/.nuget $RUNTIME_ARTIFACTS/obj

# Install production runtime + SDK
RUN curl -OL https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt update && \
    apt install -y dotnet-runtime-8.0 dotnet-sdk-8.0


# Install Rust (CARGO_HOME var)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile=minimal --default-toolchain nightly

WORKDIR /dotnetdll
CMD ["/cargo/bin/cargo", "-Z", "sparse-registry", "test"]
