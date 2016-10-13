# ten-ply-crest

LetsEncrypt middleware for Express with pluggable data store

## Installation
```sh
npm install --save ten-ply-crest
```

## Introduction

**ten-ply-crest** is a LetsEncrypt client that does not touch the filesystem or make assumptions about your architecture.  Almost every existing client stores sensitive SSL keys, certs, and challenges in the filesystem, and assumes it is running on a public-facing server.

In reality many of us these days are using a containerized architecture with a sharable, secured data store.  Containers are designed to be disposable and there may be reasons to run more than one instance of a LetsEncrypt client in tandem.

Therefore, **ten-ply-crest**:
  * Can be run behind any load-balancer
  * Can work independently or in a cluster (just set `Store.cacheEnabled = false`)
  * Can be attached to any existing Express app as simple middleware
  * Can use any backend data store (defaults to hashicorp/vault)
  * Can self-register route with hashicorp/consul
  * Can watch Consul service list to automatically generate certs for new domains
  * Designed for use in a HA, containerized environment (i.e. Joyent Cloud, Docker, Heroku)
  * Designed not to interfere with any of the existing stack, only responding to specific LetsEncrypt calls and routes
  * Never needs to alter the filesystem
  * Completely customizable and extendable class structure
  * Cleanly separates concerns:
    - controller (Express routes)
    - model (data store for certs)
    - adapter (LetsEncrypt client)

## Usage

### Standalone

```sh
npm start
```

### Middleware

From `src/server.coffee`
```coffee
    options =
      logger:         console
      advertise_addr: EXPRESS_APP_IP
      advertise_port: EXPRESS_APP_PORT
      consul_addr:    CONSUL_ADDR or "127.0.0.1"

    tpc = new TenPly options
    app.use tpc.middleware()

```

```
> we register ourselves for route http://*/.well-known/*

< when a service registers, it registers tag ssl

> we watch the list of services tagged ssl
when this list changes, we get all these services and their tags
we keep all the tags that are urlprefix
for each domain + its subdomains
we get the unique list of domains+subdomains
if we don't have this domain in our vault list, we generate a letsencrypt cert
we store the cert in the vault with a lease 15 days before expiration, and we cache it
when the load-balancer asks for the cert we hand it the cert
```

## License

MIT
