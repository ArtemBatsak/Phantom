# Phantom

Phantom is a lightweight networking proxy designed to work together with Obelisk.

It allows servers located behind NAT to accept connections from the public internet by establishing a persistent outbound connection to an Obelisk gateway.

Phantom acts as a transport proxy that forwards traffic between remote clients and a local service.

#Overview

Many environments (home networks, private infrastructure, corporate networks) place servers behind NAT, making them unreachable from the public internet.

Phantom solves this by creating a reverse connection to an Obelisk server that has a public IP address.

Once connected, Phantom receives incoming traffic through the gateway and forwards it to a local server.

## Architecture

![Architecture](images/architecture.png)

## Connection flow

Phantom establishes a persistent outbound connection to Obelisk.

This connection acts as a control channel.

Obelisk assigns a public port.

When a client connects to that port:

traffic is forwarded through the tunnel

Phantom connects to the configured local server

data flows between both endpoints.

## Key Features

Reverse proxy for services behind NAT

Lightweight TCP forwarding

TLS-protected control channel

Configurable connection pool

Designed for low resource usage

Simple architecture

## Security Model

The control connection between Phantom and Obelisk is protected using TLS.

TLS termination is handled exclusively by Obelisk, which holds the certificate.

Connections between Phantom and the local server are not encrypted.

This design choice:

reduces CPU overhead

minimizes latency

assumes the local network environment is already trusted or protected.

## Use Cases

Home-hosted game servers

Run high-performance servers at home while using a cheap VPS as a public gateway.

Dependencies

## Phantom relies on several well-known C++ libraries:

Asio

OpenSSL

spdlog

cpp-httplib "in the future"

nlohmann-json

All dependencies are managed through vcpkg using the manifest mode.

Requirements

C++20 compatible compiler

CMake 3.16+

vcpkg

## Configuration

Example parameters:

SERVER_IP = example.com

LOCAL_IP = 127.0.0.1

CONTROL_PORT = 4455

LOCAL_PORT = 55555

ID_CLIENT = 1234567

POOL_SIZE = **1**

Specifies the number of pre-established sockets maintained in the connection pool.

Phantom keeps a pool of open connections to Obelisk that are ready to be used when incoming traffic arrives. After each connection is consumed, Phantom automatically creates a new socket to maintain the configured pool size.

The recommended value is 1, which is sufficient for most scenarios with low or moderate traffic.

If you expect frequent or highly concurrent client connections, increasing this value may improve responsiveness by reducing the time required to establish new transport connections.

##Project Structure
src/            source code
vcpkg.json      dependency manifest
CMakeLists.txt  build configuration
