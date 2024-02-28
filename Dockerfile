# syntax=docker/dockerfile:1

# Includes dependencies for building the local runtime from scratch
FROM mcr.microsoft.com/dotnet-buildtools/prereqs:centos-7

# Environment variables
ENV RUNTIME_ARTIFACTS=/runtime-8.0.2/artifacts DOTNET_SDK=dotnet CARGO_HOME=/cargo

# Download/extract runtime
WORKDIR /
RUN wget -nv https://github.com/dotnet/runtime/archive/refs/tags/v8.0.2.tar.gz && \
    tar xzf v8.0.2.tar.gz && \
    rm v8.0.2.tar.gz

# Build runtime
WORKDIR /runtime-8.0.2
RUN ./build.sh clr+libs -rc debug && \
    rm -rf /root/.local/share/NuGet /root/.nuget $RUNTIME_ARTIFACTS/obj

# Install production runtime + SDK
RUN rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm && \
    yum -y install dotnet-sdk-7.0 dotnet-runtime-7.0

# Install Rust (CARGO_HOME var)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile=minimal --default-toolchain nightly

WORKDIR /dotnetdll
CMD ["/cargo/bin/cargo", "-Z", "sparse-registry", "test"]
