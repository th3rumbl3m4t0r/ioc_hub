# JA3 TLS-fingerprint binding (optional) — for egress proxies like Zscaler

## What this is for

IoCHub binds each session token to the client's **source IP**. Behind a
corporate egress proxy such as **Zscaler**, a single user's requests can come
from a *changing pool* of source IPs (different egress nodes, shifting ASNs/
ranges), which would otherwise log the user out repeatedly.

To handle this, IoCHub can fall back to the client's **JA3 TLS fingerprint**:

1. If the request comes from the **same source IP** the token was issued to →
   allowed (fast path).
2. Otherwise, if a **JA3 fingerprint** was captured at login and the request's
   JA3 **matches** → allowed (this is how a session survives an IP change).
3. Otherwise → rejected.

Zscaler (and similar) present a **highly standardised** TLS ClientHello, so the
JA3 is stable even as the egress IP rotates — which is exactly what makes this
work.

## The hard architectural fact

**The IoCHub backend cannot compute JA3 itself.** JA3 is derived from the raw
TLS ClientHello (TLS version + cipher list + extensions + curves + EC point
formats). In this deployment Apache **terminates TLS** and forwards plain HTTP
to the backend on loopback, so by the time a request reaches the backend the
ClientHello is gone.

**Stock Apache / mod_ssl cannot produce JA3 either.** mod_ssl only exposes the
*negotiated* cipher and protocol (`SSL_CIPHER`, `SSL_PROTOCOL`) — not the full
*offered* cipher list and extensions that JA3 requires. There is no built-in
JA3 in Apache.

So the JA3 value must be computed by a **JA3-aware component at the TLS edge**
and handed to the backend as a **trusted HTTP header**. The backend reads that
header (configured via `IOCHUB_JA3_HEADER`); it never trusts a value a browser
could set, because:

- the backend listens only on `127.0.0.1`, so only the local reverse proxy
  reaches it, and
- the Apache vhost does `RequestHeader unset X-JA3-Hash` to strip any
  client-supplied copy before proxying.

## Enabling it in IoCHub

1. Stand up a JA3 source (next section) that injects the fingerprint.
2. In the systemd unit (`/etc/systemd/system/iochub.service`), set the header
   name the backend should trust:

   ```
   Environment=IOCHUB_JA3_HEADER=X-JA3-Hash
   ```

   Then `systemctl daemon-reload && systemctl restart iochub`.

3. Leave it **unset** to keep pure source-IP binding (the default; no JA3).

## How to source the JA3 fingerprint (pick one)

### Option A — A JA3-aware reverse proxy in front (recommended)

Put a proxy that computes JA3 in front of (or in place of) Apache's TLS role.
It terminates TLS, computes the JA3, **strips any client-supplied fingerprint
header**, sets the trusted header, and forwards on.

- **HAProxy** can compute a JA3/JA4 fingerprint from the ClientHello and set it
  as a request header (recent versions; via native fetches or a small Lua
  helper). Terminate TLS at HAProxy, set `X-JA3-Hash`, forward to Apache/the
  backend.
- **Nginx with a JA3 module** (one of the community `ssl_ja3` builds) exposes
  the fingerprint as a variable you can pass with
  `proxy_set_header X-JA3-Hash $ssl_ja3;`.

Topology: `client → [JA3 proxy: TLS term + fingerprint] → Apache → backend`,
or the JA3 proxy can proxy straight to the backend and replace Apache.

Whatever you use, two rules are non-negotiable:
1. the JA3 proxy MUST overwrite/strip any inbound copy of the header (so a
   client can't forge its own JA3), and
2. only that trusted proxy chain may reach the backend.

If the JA3 proxy passes its fingerprint to Apache under a *different* header
name (e.g. `X-Edge-JA3`), copy it into the trusted header in the Apache vhost
(commented example included there) — and keep the `RequestHeader unset` line so
the client copy is still dropped.

### Option B — A tiny custom JA3 terminator

A small TLS-terminating proxy (e.g. in Rust with a library that surfaces the
ClientHello) that computes JA3, sets `X-JA3-Hash`, and forwards plain HTTP to
the backend. More control, but it is another component to build and secure.

### Not an option — Apache env vars

`SSLOptions +StdEnvVars` only gives you the negotiated cipher/protocol, which is
**not** JA3 and is far too coarse to distinguish clients. Don't rely on it.

## Security trade-off (read before enabling)

JA3 fallback **loosens** the binding from "same IP" to "same IP **or** same TLS
fingerprint." Because Zscaler standardises TLS, **all users behind the same
Zscaler tenant share essentially the same JA3** — so JA3 does not distinguish
one Zscaler user from another. The effective rule becomes:

> a token works from its original IP, **or** from any IP that presents the same
> (corporate) TLS fingerprint.

Combined with the secret bearer token (256-bit, server-stored only as needed)
and the short token TTL, this is a reasonable trade for a corporate-internal
tool whose users all egress through the same proxy. But understand that a
**stolen token** replayed **from behind the same Zscaler tenant** would pass the
JA3 check. If that residual risk is unacceptable, leave JA3 disabled and keep
strict IP binding.
