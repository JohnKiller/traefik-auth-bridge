# Protocol and security design

This document defines the protocol expected by Traefik Auth Bridge, its trust boundaries, and its deliberate limitations.

## Components and trust boundaries

The system has four actors:

- The browser, which is untrusted.
- Traefik and this middleware, which enforce access before requests reach an upstream service.
- The authorization portal, which authenticates users, applies authorization policy, and issues one-time codes.
- The upstream service, which is unaware of the authentication flow and must not be trusted to enforce it.

The middleware trusts a successful code redemption response from the configured portal endpoint. The portal trusts only its own stored authorization grants. Neither component trusts callback query parameters as proof of authorization.

## Authorization request

For a request without a valid cookie, the middleware builds the original absolute URL from the request scheme, host, path, and query string. It generates 32 random bytes, stores the Base64URL value in a temporary host-only `HttpOnly` cookie whose name is derived from the state, and redirects to `authorizationURL`. The original URL is placed in `returnURLParameter` and the random value in `stateParameter`. Flow-specific cookie names allow multiple authorization requests from the same browser to remain pending without overwriting each other.

When `protectedPath` is narrower than `/`, requests outside that exact path segment and its descendants pass directly to the upstream without cookie inspection. The callback path is always intercepted, including when it lies outside the protected subtree.

The portal must treat the return URL as untrusted input. It must validate the scheme, origin, callback path, and service registration before presenting or completing authorization. A suffix-only hostname check is not sufficient for a general-purpose deployment. The portal must preserve the state value and bind it to the authorization grant.

The portal is responsible for authenticating the user and deciding whether that user may access the requested service.

## One-time authorization code

After authorization, the portal generates an opaque code using a cryptographically secure random number generator. A recommended representation is 32 random bytes encoded with unpadded Base64URL.

The portal stores a record keyed by a hash of the code:

```text
SHA-256(code) -> {
    return_url,
    subject,
    service_id,
    state,
    expires_at
}
```

The exact record may contain additional policy or identity information. The plaintext code should not be stored when a hash is sufficient.

The portal redirects the browser to the registered callback path on the protected origin. The code and unchanged state are carried in their configured callback query parameters.

Codes must be:

- cryptographically unpredictable;
- short-lived, normally 30–60 seconds;
- scoped to the validated service and return URL;
- consumed atomically;
- rejected after their first successful redemption.

## Code redemption

The middleware intercepts `callbackPath`; the upstream service never receives this request. Before redemption, it derives the flow-specific cookie name from the callback state, compares the callback state with that temporary host-only cookie using a constant-time comparison, and consumes the cookie. A missing or mismatched value is rejected without contacting the portal. It then sends the code to `redeemURL` as an `application/x-www-form-urlencoded` POST. After a successful authorization, every remaining pending state cookie sent by the browser is cleared.

The portal must perform an atomic lookup-and-delete operation. Concurrent redemption attempts for the same code must result in at most one successful response.

A successful response is:

```json
{
  "active": true,
  "rd": "https://service.example.org/original/path",
  "state": "browser-state"
}
```

The middleware accepts the response only when:

- the HTTP status is `200`;
- the body is valid JSON and `active` is `true`;
- the redeemed state matches the callback and browser state;
- `rd` is an absolute HTTPS URL;
- the `rd` authority exactly matches the authority of the callback request.

The middleware does not use a browser-provided return URL during cookie creation. It uses only the return URL recovered by the portal from the consumed server-side grant.

When `redeemURL` crosses an untrusted network, it must use HTTPS with normal certificate validation. A private, trusted network may use HTTP if that risk is acceptable to the operator.

## Session cookie

After successful redemption, the middleware creates a cookie with this wire format:

```text
v1.<unix-expiration>.<base64url-mac>
```

It derives a service-specific key:

```text
service_key = HMAC-SHA-256(
    master_key,
    "traefik-cookie-auth:key:v1:" + service_id
)
```

The cookie MAC is:

```text
HMAC-SHA-256(
    service_key,
    "traefik-cookie-auth:cookie:v1:" + service_id + ":" + unix_expiration
)
```

MAC comparison is constant-time. The embedded expiration, not the browser-provided `Expires` or `Max-Age` attribute, is authoritative.

The default cookie is named `__Host-traefik-auth` and is issued with:

```text
Path=/; Secure; HttpOnly; SameSite=Lax
```

No `Domain` attribute is set. Each hostname therefore receives an independent host-only cookie, even when several hostnames use the same `serviceID`.

The cookie is authenticated but not encrypted. Its version and expiration are visible to the browser. They contain no secret information.

## Master key and service isolation

The master key must contain at least 32 bytes generated by a cryptographically secure random number generator. Production deployments should provide it through `masterKeyFile`, mounted as a file readable by Traefik. It must not be placed in Docker labels or committed to source control.

The mutually exclusive `masterKey` option accepts inline key material for catalog validation and development environments. Operators should assume that inline dynamic configuration and Docker labels are observable through control-plane APIs and diagnostic tooling.

Each stable `serviceID` derives a different HMAC key. A cookie valid for one service ID is not valid for another, even when both use the same master key.

Changing the master key, `serviceID`, or signed format invalidates existing cookies. This project deliberately does not implement key rotation or compatibility with previous keys.

Key derivation isolates cookie namespaces, but it does not protect against complete compromise of Traefik: a process that can read the master key can derive every service key.

## Replay and revocation

Authorization codes are one-time values and must not survive redemption. Session cookies are bearer credentials and may be replayed by anyone who steals them until expiration.

The middleware is stateless and does not support individual cookie revocation. Revocation requires one of:

- rotating the master key, which invalidates every session;
- reducing cookie lifetime;
- adding a server-side session or denylist mechanism.

Binding cookies to IP addresses or User-Agent strings is intentionally avoided because it is brittle and does not reliably prevent theft.

## CSRF and application security

This middleware controls whether a request may reach an upstream service. It does not provide application-level CSRF protection, per-action authorization, input validation, content security policy, or logout propagation.

`SameSite=Lax` reduces some cross-site cookie delivery but is not a substitute for CSRF protection in state-changing upstream applications.

## Browser binding with state

The temporary state cookie binds the authorization grant to the browser that initiated the flow. Its name consists of the configured prefix and the Base64URL-encoded SHA-256 digest of the state. A callback URL copied to another browser fails because that browser does not possess the matching host-only `HttpOnly` cookie. Authenticated redemption also confirms that the portal bound the same state to the one-time code.

State is consumed when callback processing starts. A failed or interrupted redeem therefore requires a new authorization flow. This fail-closed behavior prevents repeated attempts with the same browser state.

## Operational recommendations

- Use HTTPS for authorization and callback endpoints.
- Avoid recording authorization codes in access logs, analytics, and referrer data.
- Restrict portal return URLs to registered origins and callback paths.
- Consume authorization codes atomically.
- Preserve state in the portal grant and return it from both callback and redeem.
- Use at least 32 random bytes for the master key.
- Keep the master key readable only by the Traefik process.
- Use a stable and unique `serviceID` for each security boundary.
- Keep cookie lifetimes as short as operationally practical.
