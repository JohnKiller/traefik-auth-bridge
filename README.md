# Traefik Auth Bridge

Traefik Auth Bridge is a Traefik middleware plugin that protects otherwise unauthenticated upstream services through an external authorization portal.

Unauthenticated requests are redirected to the portal. After authorization, the portal returns a short-lived, one-time code to the middleware callback. The middleware redeems the code through a back-channel request and creates a host-only, HMAC-authenticated session cookie. Subsequent requests are validated locally without contacting the portal.

The upstream application does not need to implement authentication routes, callbacks, sessions, or middleware.

## Flow

1. A request without a valid session cookie reaches the middleware.
2. The middleware creates a temporary browser-bound `state` value, stores it in a flow-specific cookie, and redirects the browser to `authorizationURL`, adding the original URL and state under their configured parameters.
3. The portal authenticates and authorizes the user.
4. The portal creates a short-lived, opaque, one-time code bound to the state and redirects the browser to `callbackPath` on the original host with both values.
5. The middleware verifies the browser state, sends the code to `redeemURL`, and verifies that the redeemed grant contains the same state.
6. A successful redeem response causes the middleware to issue a signed, host-only session cookie and redirect to the original URL.
7. Later requests are authorized locally by validating the cookie signature and expiration.

See [DESIGN.md](DESIGN.md) for the complete protocol and security model.

## Installation

### Plugin Catalog

Declare the plugin in Traefik's static configuration:

```yaml
experimental:
  plugins:
    authbridge:
      moduleName: github.com/JohnKiller/traefik-auth-bridge
      version: v0.1.0
```

Equivalent CLI flags:

```yaml
command:
  - --experimental.plugins.authbridge.modulename=github.com/JohnKiller/traefik-auth-bridge
  - --experimental.plugins.authbridge.version=v0.1.0
```

### Local development

Place the repository at:

```text
plugins-local/src/github.com/JohnKiller/traefik-auth-bridge
```

Then enable it in Traefik's static configuration:

```yaml
experimental:
  localPlugins:
    authbridge:
      moduleName: github.com/JohnKiller/traefik-auth-bridge
```

Traefik loads plugin source only during startup. Restart Traefik after changing the plugin.

## Configuration

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `serviceID` | yes | — | Stable, unique identifier used to derive the service-specific HMAC key. |
| `masterKeyFile` | one of the two | — | File containing at least 32 bytes of random master key material. Recommended for production. |
| `masterKey` | one of the two | — | Inline master key of at least 32 bytes. Intended for testing because configuration systems may expose it. |
| `authorizationURL` | yes | — | Absolute URL of the portal authorization page. Existing query parameters are preserved. |
| `returnURLParameter` | no | `rd` | Query parameter added to `authorizationURL` with the original absolute request URL. |
| `stateParameter` | no | `state` | Query parameter carrying the browser-bound state through authorization and callback. |
| `stateCookieName` | no | `__Host-traefik-auth-state` | Prefix for temporary, flow-specific host-only cookies used to bind concurrent flows to the initiating browser. |
| `stateTTL` | no | `300` | Lifetime of the temporary state cookie in seconds. |
| `protectedPath` | no | `/` | Absolute path subtree that requires authentication. `/admin` protects `/admin` and `/admin/...`, but not `/administrator`. |
| `callbackPath` | no | `/_auth/callback` | Path intercepted by the middleware to receive the authorization code. |
| `authorizationCodeParameter` | no | `code` | Query parameter containing the code on the browser callback. |
| `redeemURL` | yes | — | Portal endpoint called by the middleware to redeem a code. |
| `redeemCodeParameter` | no | `code` | Form field used to send the code to `redeemURL`. |
| `cookieName` | no | `__Host-traefik-auth` | Session cookie name. Keep the `__Host-` prefix unless its semantics are understood. |
| `cookieTTL` | no | `3600` | Session lifetime in seconds. |

### Docker labels

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.app.middlewares=app-auth
  - traefik.http.middlewares.app-auth.plugin.authbridge.serviceID=my-service
  - traefik.http.middlewares.app-auth.plugin.authbridge.masterKeyFile=/run/secrets/auth-cookie-master-key
  - traefik.http.middlewares.app-auth.plugin.authbridge.authorizationURL=https://login.example.net/authorize
  - traefik.http.middlewares.app-auth.plugin.authbridge.returnURLParameter=return_to
  - traefik.http.middlewares.app-auth.plugin.authbridge.stateParameter=state
  - traefik.http.middlewares.app-auth.plugin.authbridge.stateTTL=300
  - traefik.http.middlewares.app-auth.plugin.authbridge.protectedPath=/private
  - traefik.http.middlewares.app-auth.plugin.authbridge.callbackPath=/_auth/callback
  - traefik.http.middlewares.app-auth.plugin.authbridge.authorizationCodeParameter=code
  - traefik.http.middlewares.app-auth.plugin.authbridge.redeemURL=https://login.example.net/redeem
  - traefik.http.middlewares.app-auth.plugin.authbridge.redeemCodeParameter=code
  - traefik.http.middlewares.app-auth.plugin.authbridge.cookieTTL=3600
```

Mount the master key only in the Traefik container:

```yaml
volumes:
  - ./secrets/auth-cookie-master-key:/run/secrets/auth-cookie-master-key:ro
```

Generate a 32-byte master key:

```bash
openssl rand -out auth-cookie-master-key 32
chmod 600 auth-cookie-master-key
```

Do not place the master key directly in Docker labels.

`masterKey` and `masterKeyFile` are mutually exclusive. The inline `masterKey` option allows the Traefik Plugin Catalog to instantiate the middleware from `.traefik.yml` without an externally mounted secret. Prefer `masterKeyFile` for real deployments.

## Authorization portal requirements

The portal must implement two endpoints.

### Authorization endpoint

The browser is redirected to `authorizationURL`. The query parameter configured by `returnURLParameter` contains the original absolute URL, and `stateParameter` contains a cryptographically random value tied to a temporary host-only browser cookie. Each pending flow uses a distinct cookie so concurrent requests cannot overwrite one another. State cookies expire after `stateTTL` seconds and all remaining pending state cookies are cleared after a successful authorization.

After authenticating and authorizing the user, the portal must:

1. Validate the return URL against its registered services and allowed origins.
2. Generate a cryptographically random, opaque authorization code.
3. Store only a hash of the code, together with the validated return URL, the received state, and a short expiration.
4. Redirect the browser to `callbackPath` on the return URL's origin.
5. Put the code in `authorizationCodeParameter` and return the unchanged state in `stateParameter`.

Example callback:

```text
https://service.example.org/_auth/callback?code=opaque-one-time-code&state=browser-state
```

Codes should contain at least 128 bits of entropy; 256 bits are recommended. They should expire within roughly 30–60 seconds.

### Redeem endpoint

The middleware sends an HTTP `POST` with content type `application/x-www-form-urlencoded`. The code is sent using `redeemCodeParameter`.

On a valid code, the portal must atomically consume it and return HTTP `200` with:

```json
{
  "active": true,
  "rd": "https://service.example.org/original/path",
  "state": "browser-state"
}
```

Any invalid, expired, or already consumed code must return a non-`200` response. The code must never be reusable.

The state returned by redeem must be the value stored with the grant, not a value copied from the redeem request.

## Compared with ForwardAuth

Traefik's built-in ForwardAuth middleware delegates every protected request to an authorization endpoint. Traefik Auth Bridge delegates only the interactive authorization exchange and validates subsequent requests locally with an HMAC-authenticated cookie.

| | Traefik Auth Bridge | ForwardAuth |
| --- | --- | --- |
| Authorization service calls | During login and code redemption | On every protected request |
| Session validation | Local HMAC cookie validation | Authorization endpoint response |
| Upstream changes | None | None |
| Identity headers | Not currently propagated | Supports `authResponseHeaders` |
| Immediate central revocation | No; cookies remain valid until expiration | Yes, when enforced by the authorization endpoint |
| Authorization service outage | Existing sessions continue working | Protected requests normally fail |
| Portal protocol | One-time code, state, and redeem response | HTTP status response to forwarded request |
| Traefik feature type | Experimental plugin | Built-in middleware |

Use ForwardAuth when authorization must be evaluated centrally on every request, immediate revocation is required, or the upstream needs identity headers. Use Traefik Auth Bridge when the upstream is completely authentication-unaware and local stateless session validation is preferred.

## Multiple services and domains

Use a distinct `serviceID` for each security boundary. The plugin derives a separate HMAC key from the shared master key and `serviceID`.

A service may be exposed through multiple hostnames. Cookies are host-only, so each hostname receives its own cookie after completing the callback, while all hostnames may share the same `serviceID`.

## License

[MIT](LICENSE)
