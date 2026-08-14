# CrowdSec Bouncer for Caddy

[![Go Report Card](https://goreportcard.com/badge/github.com/hslatman/caddy-crowdsec-bouncer)](https://goreportcard.com/report/github.com/hslatman/caddy-crowdsec-bouncer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> A [Caddy](https://caddyserver.com/) module that blocks malicious traffic based on decisions made by [CrowdSec](https://crowdsec.net/).

## Table of Contents
- [CrowdSec Bouncer for Caddy](#crowdsec-bouncer-for-caddy)
  - [Table of Contents](#table-of-contents)
  - [Description](#description)
    - [What is CrowdSec?](#what-is-crowdsec)
  - [Usage](#usage)
    - [Option 1: Docker Build](#option-1-docker-build)
    - [Option 2: Custom Go Build (xcaddy)](#option-2-custom-go-build-xcaddy)
    - [Configuration](#configuration)
  - [Demo](#demo)
  - [Utilities](#utilities)
    - [Usage](#usage-1)
  - [Client IP](#client-ip)
  - [Things That Can Be Done](#things-that-can-be-done)
    - [Contributing](#contributing)

## Description

The Caddy CrowdSec Bouncer consists of five components:

- **Caddy App**: Responsible for communicating with CrowdSec via the *Local API* and keeping track of its decisions. It supports both *StreamBouncer* (HTTP polling) and *LiveBouncer* (a request is made on every incoming connection).
- **Bouncer HTTP Handler**: Checks client IPs of incoming HTTP requests against the decisions stored by the App. Multiple independent HTTP Handlers and Connection Matchers can share the storage exposed by the App.
- **Layer 4 Connection Matcher**: Matches TCP and UDP IP addresses against the CrowdSec *Local API*. Uses the [Caddy Layer 4 app](https://github.com/mholt/caddy-l4).
- **AppSec HTTP Handler**: Communicates with an AppSec component configured on your CrowdSec deployment, seamlessly checking incoming HTTP requests against configured rulesets.
- **`caddy crowdsec` Command**: Offers useful Caddy CLI commands for your CrowdSec integration.

### What is CrowdSec?

CrowdSec is a free and open source security automation tool that uses local logs and a set of scenarios to infer malicious intent. 
In addition to operating locally, an optional community integration is also available, through which crowd-sourced IP reputation lists are distributed.

The architecture of CrowdSec is very modular.
At its core is the CrowdSec Security Engine, which keeps track of all data and related systems.
Bouncers are pieces of software that perform specific actions based on the decisions of the Security Engine.

## Usage

> [!TIP]
> You can find full setup examples in /examples inside this repository.

You can use the bouncer by either building a custom Caddy image with Docker or by fetching the required Go modules directly into your own build.

> **Note:** You will need a recent version of **Caddy (v2.7.3+)** and **Go (1.20+)**.

### Option 1: Docker Build

To include the bouncer in a Docker Image using `xcaddy`. Create a `Dockerfile`:

```dockerfile
ARG CADDY_VERSION=2

FROM caddy:${CADDY_VERSION}-builder-alpine AS builder

RUN xcaddy build \
    --with github.com/mholt/caddy-l4 \
    --with github.com/caddyserver/transform-encoder \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@main \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@main \
    --with github.com/hslatman/caddy-crowdsec-bouncer/layer4@main

FROM caddy:${CADDY_VERSION}

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

### Option 2: Custom Go Build

If you are compiling outside of Docker, you can fetch the modules using `go get`:

```bash
# get the CrowdSec Bouncer HTTP handler
go get github.com/hslatman/caddy-crowdsec-bouncer/http

# get the CrowdSec layer4 connection matcher (only required for TCP/UDP level blocking)
go get github.com/hslatman/caddy-crowdsec-bouncer/layer4

# get the AppSec HTTP handler (only required for CrowdSec AppSec support)
go get github.com/hslatman/caddy-crowdsec-bouncer/appsec
```

### Configuration

Configuration using a Caddyfile is supported for HTTP handlers and Layer 4 matchers.

#### Configuration Options

| Directive                 | Description                                                                                                                                                          | Default                  |
|:--------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------|
| `api_url`                 | The URL of the CrowdSec Local API.                                                                                                                                   | `http://127.0.0.1:8080/` |
| `api_key`                 | The API key to authenticate with the Local API.                                                                                                                      | `<empty>` *(required)*   |
| `disable_streaming`       | Falls back to LiveBouncer mode (queries API per request).                                                                                                            | `false`                  |
| `metrics_interval`        | Interval for pushing metrics to the Local API.                                                                                                                       | `0s` *(disabled)*        |
| `enable_caddy_metrics`    | Enables emitting bouncer metrics at Caddy's `/metrics` endpoint.                                                                                                     | `false`                  |
| `ticker_interval`         | Interval for pulling decisions from the Local API.                                                                                                                   | `60s`                    |
| `enable_hard_fails`       | Caddy fails to start if CrowdSec API is unreachable.                                                                                                                 | `false`                  |
| `captcha_provider`        | CAPTCHA provider: `recaptcha`, `hcaptcha`, or `turnstile`. Setting any CAPTCHA option requires a complete CAPTCHA configuration.                                     | `<empty>` *(disabled)*   |
| `captcha_site_key`        | Public site key issued by the CAPTCHA provider.                                                                                                                      | `<empty>` *(required)*   |
| `captcha_secret_key`      | Secret verification key issued by the CAPTCHA provider.                                                                                                             | `<empty>` *(required)*   |
| `captcha_signing_key`     | Independent secret used to sign CAPTCHA state cookies; must contain at least 32 bytes.                                                                                | `<empty>` *(required)*   |
| `captcha_template_path`   | Optional path to a custom HTML challenge template.                                                                                                                   | `<empty>`                |
| `captcha_expiration`      | How long a successful CAPTCHA remains valid (maximum `24h`).                                                                                                         | `1h`                     |
| `captcha_timeout`         | Maximum time for server-side verification with the CAPTCHA provider (maximum `1m`).                                                                                 | `5s`                     |
| `appsec_url`              | The URL of the CrowdSec AppSec component.                                                                                                                            | `<empty>` *(disabled)*   |
| `appsec_max_body_bytes`   | Maximum request body size sent to AppSec.                                                                                                                            | `0` *(full request)*     |
| `appsec_timeout`          | Maximum time for request to AppSec component.                                                                                                                        | `2s`                     |
| `appsec_fail_open`        | Ignore AppSec component connection errors.                                                                                                                           | `false`                  |
| `enable_caddy_error`      | Propagates decisions as Caddy errors to allow custom error pages. **Warning:** Ensure `handle_errors` routes are strictly static to avoid resource exhaustion (DoS). | `false`                  |

#### Example

```Caddyfile
{
  debug

  crowdsec {
    api_url http://localhost:8080
    api_key <api_key>
    ticker_interval 15s
    appsec_url http://localhost:7422
    #captcha_provider turnstile
    #captcha_site_key {$CROWDSEC_CAPTCHA_SITE_KEY}
    #captcha_secret_key {$CROWDSEC_CAPTCHA_SECRET_KEY}
    #captcha_signing_key {$CROWDSEC_CAPTCHA_SIGNING_KEY}
    #captcha_expiration 1h
    #captcha_timeout 5s
    #disable_streaming
    #enable_hard_fails
    #enable_caddy_error
  }

  layer4 {
    localhost:4444 {
      @crowdsec crowdsec
      route @crowdsec {
        proxy {
          upstream localhost:6443
        }
      }
    }
  }
}

localhost:8443 {
  route {
    crowdsec
    respond "Allowed by Bouncer!"
  }
}

localhost:7443 {
  route {
    appsec
    respond "Allowed by AppSec!"
  }
}

localhost:6443 {
  route {
    crowdsec
    appsec
    respond "Allowed by Bouncer and AppSec!"
  }
}
```

#### CAPTCHA Remediation

CAPTCHA support is opt-in. Configure all four required CAPTCHA options to turn a CrowdSec `captcha` decision into an interactive browser challenge. When all CAPTCHA options are omitted, the existing fail-closed behavior is preserved: `captcha` decisions are applied as HTTP 403 bans. A partial configuration prevents Caddy from starting.

CAPTCHA configuration belongs to the global `crowdsec` app. One provider profile is therefore shared by every site and by both HTTP remediation handlers in the same Caddy process.

The equivalent global app fields can also be supplied in Caddy's native JSON configuration:

```json
{
  "apps": {
    "crowdsec": {
      "api_key": "{env.CROWDSEC_API_KEY}",
      "captcha_provider": "turnstile",
      "captcha_site_key": "{env.CROWDSEC_CAPTCHA_SITE_KEY}",
      "captcha_secret_key": "{env.CROWDSEC_CAPTCHA_SECRET_KEY}",
      "captcha_signing_key": "{env.CROWDSEC_CAPTCHA_SIGNING_KEY}"
    }
  }
}
```

The bouncer renders a challenge with status 200 and verifies the provider token server-side. The default template submits each proof automatically after the provider reports success, including a new proof after a rejected attempt. A persistent server-side rejection, such as a hostname or action mismatch, can therefore cause repeated verification attempts; use the manual template if that behavior is unsuitable. At most 64 provider checks per Caddy process and four per client IP can be in flight at once. Additional checks fail closed.

A successful proof creates a signed, host-only, `HttpOnly`, `SameSite=Strict` cookie bound to the client IP and redirects to the exact original relative URI with status 303. The cookie contains validation state and opaque integrity tags, not the original path or query string. That clearance applies to CAPTCHA decisions for the same host, client IP, and configured provider profile until `captcha_expiration`; it never bypasses a `ban` or an unknown fail-closed action. The cookie name `crowdsec_captcha` is reserved while CAPTCHA is enabled; an application cookie with the same name will invalidate the CAPTCHA flow.

Challenges are only rendered for `GET` and `HEAD`; other methods fail closed until the client clears the CAPTCHA through a browser navigation. Request bodies are never replayed or sent upstream. While CAPTCHA is enabled, the query parameter name `__crowdsec_captcha` is reserved for internal submissions; any request containing it is intercepted and never sent to AppSec or the application. A `ban` decision always takes precedence over a solved CAPTCHA. When both HTTP handlers are used in one route, keep `crowdsec` before `appsec`, as shown above, so stored decisions are evaluated before an AppSec challenge response.

Keep `captcha_secret_key` and `captcha_signing_key` in environment variables or a secrets manager. The signing key must be different from the provider secret and contain at least 32 bytes; for example, generate one with `openssl rand -base64 32`. Restrict the provider site key to every hostname served by this Caddy configuration using [reCAPTCHA domain validation](https://developers.google.com/recaptcha/docs/domain_validation), the [hCaptcha domain allowlist](https://docs.hcaptcha.com/configuration/#domain-allowlist), or [Turnstile hostname management](https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/). In particular, hCaptcha site keys work on any domain until Domain Allowlisting is enabled in the hCaptcha dashboard. Use separate provider credentials for development and production.

Use HTTPS in production. The clearance cookie receives `Secure` only when the request reaches Caddy with TLS state. If another proxy terminates TLS and connects to Caddy over plain HTTP, either preserve TLS to Caddy or account for the resulting non-`Secure` cookie in the deployment threat model. All Caddy instances serving the same hosts must use the same provider, site key, secret key, signing key, and CAPTCHA expiration so that challenges and proofs remain valid across replicas. Configure Caddy's [trusted proxies](https://caddyserver.com/docs/caddyfile/options#trusted-proxies) correctly: the client IP resolved by Caddy is both sent to the provider and included in the signed proof binding. The cookie remains browser-local, so clients behind the same NAT do not share clearance; however, an IP change or inconsistent proxy resolution between replicas invalidates an existing clearance.

Provider timeouts, malformed responses, invalid internal submissions, and rendering failures all fail closed as bans. The challenge itself is written directly and does not use `handle_errors`; a ban fallback still respects `enable_caddy_error`. Metrics record a rendered challenge as remediation `captcha`, while fail-closed fallbacks and Layer 4 enforcement are recorded as `ban`. Solved proofs and valid clearance cookies are not counted as blocked requests. Layer 4 matchers cannot present browser challenges, so they always apply CAPTCHA decisions as connection bans.

A custom template uses Go's `html/template` syntax and receives `.Provider`, `.SiteKey`, `.ScriptURL`, `.WidgetClass`, `.Action`, `.FormAction`, `.Nonce`, and `.Failed`. Preserve `.FormAction` and the provider widget fields so submissions remain internal to the bouncer. Trusted inline scripts must use `nonce="{{.Nonce}}"`; other inline scripts are blocked by the response Content Security Policy. A manual-submit example is available in [`examples/captcha-templates`](examples/captcha-templates/README.md).

Run the Caddy server

```bash
# with a Caddyfile
caddy run --config Caddyfile 
```

## Demo

This repository also contains an example using Docker inside the examples/demo folder.
Steps to run this demo are as follows:

```bash
# run CrowdSec container
docker compose up -d crowdsec

# add the Caddy bouncer, generating an API key
docker compose exec crowdsec cscli bouncers add caddy-bouncer

# copy and paste the API key in the ./examples/demo/config.json file

# run Caddy; at first run a custom build will be created using xcaddy
docker compose up -d caddy

# tail the logs
docker compose logs -tf
```

You can then access https://localhost:9443 and https://localhost:8443.
The latter is an example of using the [Layer 4 App](https://github.com/mholt/caddy-l4) and will simply proxy to port 9443 in this case. 

## Utilities

When Caddy is built with this module enabled, a new `caddy crowdsec` command will be enabled.
Its subcommands allow you to interact with your CrowdSec integration at runtime using [Caddy's Admin API](https://caddyserver.com/docs/api).
This is useful to verify the status of your integration, and check if it's configured and working properly.
The command requires the Admin API to be reachable from the system it is run from.

Support for the command is currently experimental, and will be improved and extended in future releases.
Output of the commands should not be relied upon in automated processes (yet).

### Usage

```console
$ caddy crowdsec

Commands related to the CrowdSec integration (experimental)

Usage:
  caddy crowdsec [command]

Available Commands:
  check       Checks an IP to be banned or not
  health      Checks CrowdSec integration health
  info        Shows CrowdSec runtime information
  ping        Pings the CrowdSec LAPI endpoint

Flags:
  -a, --adapter string   Name of config adapter to apply (when --config is used)
      --address string   The address to use to reach the admin API endpoint, if not the default
  -c, --config string    Configuration file to use to parse the admin address, if --address is not used
  -h, --help             help for crowdsec
  -v, --version          version for crowdsec

Use "caddy crowdsec [command] --help" for more information about a command.

Full documentation is available at:
https://caddyserver.com/docs/command-line
```

## Client IP

When your Caddy server is deployed behind a proxy (like a CDN or load balancer), the actual client IP is masked. Starting with `v0.3.1`, this module relies on Caddy's native logic (introduced in Caddy `v2.7.0` via [caddy#5104](https://github.com/caddyserver/caddy/pull/5104)) to determine the correct client IP before checking it against CrowdSec decisions.

> **Important:** Caddy uses the `X-Forwarded-For` header by default. To trust this header, you **must** configure the [`trusted_proxies`](https://caddyserver.com/docs/json/apps/http/servers/#trusted_proxies) global directive in your Caddyfile.

You can override the default header using the [`client_ip_headers`](https://caddyserver.com/docs/json/apps/http/servers/#client_ip_headers) directive.

*Note: For Caddy versions up to `v2.4.6` and older versions of this module, the [realip](https://github.com/kirsch33/realip) module is required.*

## Things That Can Be Done

- [ ] Add integration tests for the HTTP and L4 handlers
- [ ] Implement tests for IPv6 support
- [ ] Validate *project conncept* (Caddy layer 4 app: TCP working, UDP needs testing)
- [ ] Implement support for custom actions (currently defaults to block)
- [ ] Integrate with Caddy metrics
- [ ] Integrate with Caddy profiling
- [ ] Implement caching for the LiveBouncer

...and more things to come!

## Contributing

We are always open to contributions! Whether it's fixing bugs, improving documentation, or adding new features from the Roadmap above, your help is welcome. Feel free to open an issue or submit a pull request.
