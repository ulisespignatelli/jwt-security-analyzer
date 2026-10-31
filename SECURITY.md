# Security Policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately via **Security → Report a vulnerability** on this repository. Include reproduction steps and impact; I will acknowledge within 7 days.

## Security & privacy design

A JWT often **is** a credential, so the tool is built so that no token ever leaves the user's machine:

- **No backend, no network.** Static site. The CSP includes `connect-src 'none'`, so the page cannot make any network request even if it tried.
- **Strict Content-Security-Policy** (`script-src 'self'`, no inline scripts, `form-action 'none'`, `object-src 'none'`, `base-uri 'none'`).
- **Output encoding.** Every value taken from the token (header, payload, `kid`, etc.) is HTML-escaped before rendering, so a crafted token cannot inject HTML or script into the page. A regression-style token with HTML in its claims is covered by the tests.
- **HMAC verification runs locally** via the Web Crypto API (`crypto.subtle`); in Node (tests) it uses the standard `crypto` module.
- **Scope.** The secret check only tries a short, bundled list of well-known weak secrets and is limited to tokens the user pastes themselves — it is an educational demonstration, not a remote attack tool.
- **Supply chain.** Zero third-party dependencies. CodeQL and Dependabot are enabled.

## Intended use

For auditing your own tokens, learning, and assessing systems you are **authorized** to test.
