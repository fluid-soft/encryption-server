# Fluid Encryption Proxy

This project enables AI apps of your choice to use our [Fluid's Private API](https://getfluid.app/#fluidpro)'s **2nd layer encryption feature**.
Second layer encryption is an optional capability of Fluid Private API that encrypts your chat messages in transit, 
ensuring only the final [inference server](https://github.com/fluid-soft/decryption-server) can decrypt them. 
Our inference servers are operating in RAM-only mode, so even if due to some bug (extremely unlikely) some part of your conversation gets logged, it will be erased after the first server shutdown.

## Overview

The encryption proxy works as follows:

1. Run this server locally on your machine.
2. Point your favorite LLM client (e.g. Aider) to this local server (your client has to be OpenAI API compatible).
3. The proxy encrypts all messages before forwarding the Fluid Private API
4. Messages are decrypted only at the final destination where inference happens
5. Responses are encrypted and sent back through the same secure channel

This setup allows you to:
- Use any OpenAI-compatible client of your choice
- Keep your conversations private and encrypted
- Prevent intermediaries from accessing your data

## Installation

1. `git clone https://github.com/fluid-soft/encryption-server.git`
2. `go build` (you can define `PORT` env variable, default is `2222`)
3. `./encryption-server`
4. In your AI app use URL: `http://localhost:2222/v1`. As an API KEY use your Fluid's account number. 

### Prerequisites

- Go 1.23 or later (very likely it also works on earlier versions of Go)
- Git

### License
[GPL 3.0](LICENSE)