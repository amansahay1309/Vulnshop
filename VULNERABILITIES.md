# vulnShop Vulnerability Ground Truth

> ⚠️ **WARNING**
>
> vulnShop is intentionally vulnerable. It is designed exclusively for DAST/SAST/security-tool validation. Never deploy it to the public Internet or an untrusted network.

## Authentication

| ID | Vulnerability | Location | Verification |
|---|---|---|---|
| AUTH-01 | JWT `none` algorithm accepted | `decode_vulnerable_jwt()` | Forge unsigned JWT with `alg=none`, `role=admin`; call `/api/admin/users` |
| AUTH-02 | JWT signature never validated | `decode_vulnerable_jwt()` | Sign token using any arbitrary secret; call `/api/me` |
| AUTH-03 | Weak hard-coded JWT secret | `JWT_SECRET` | Secret is `secret`; sign HS256 token |
| AUTH-04 | No JWT expiry | `create_jwt()` / decoder | Login and inspect JWT; no `exp` claim |
| AUTH-05 | Web SQL injection auth bypass | `POST /login` | Username `' OR '1'='1' --` |
| AUTH-06 | API SQL injection auth bypass | `POST /api/login` | Username `' OR '1'='1' --` |

## API

| ID | Vulnerability | Location | Verification |
|---|---|---|---|
| API-01 | BOLA / IDOR user | `GET /api/users/{user_id}` | Authenticate as Alice, request `/api/users/3` |
| API-02 | BOLA / IDOR order | `GET /api/orders/{order_id}` | Authenticate as Alice, request `/api/orders/3` |
| API-03 | Excessive data exposure | `GET /api/users/{user_id}` | Response contains password, card number, API key |
| API-04 | Mass assignment | `PUT/PATCH /api/users/{user_id}` | Send `{"role":"admin"}` |
| API-05 | Privilege escalation | user update endpoint | Change normal user's role to `admin` |
| API-06 | Broken function-level authorization | `GET /api/admin/users` | Forge JWT with `role=admin` |
| API-07 | SQL injection | `GET /api/products?search=` | Use `' OR 1=1 --` |
| API-08 | Verbose errors | API error handlers | Send malformed SQL/JWT/request data |

## Web

| ID | Vulnerability | Location | Verification |
|---|---|---|---|
| WEB-01 | SQL injection | `GET /product?id=` | `/product?id=1 OR 1=1` |
| WEB-02 | SQL injection | `GET /search?q=` | `/search?q=' OR 1=1 --` |
| WEB-03 | SQL injection | `GET /account?id=` | `/account?id=1 OR 1=1` |
| WEB-04 | SQL injection | `GET /orders?id=` | `/orders?id=1 OR 1=1` |
| WEB-05 | Reflected XSS | `GET /search?q=` | `<script>alert(document.domain)</script>` |
| WEB-06 | Stored XSS | `POST /review` | `content=<script>alert(document.domain)</script>` |
| WEB-07 | Account IDOR | `GET /account?id=` | Login Alice then `/account?id=3` |
| WEB-08 | Orders IDOR | `GET /orders?id=` | Login Alice then `/orders?id=3` |
| WEB-09 | Sensitive data exposure | `/account?id=` | Card number/API key/password displayed |
| WEB-10 | CSRF | `POST /review` | Cross-site form POST can create review |
| WEB-11 | CSRF | `POST /account/update` | Cross-site form POST can change email |
| WEB-12 | Open redirect | `GET /redirect?next=` | `/redirect?next=https://example.com` |
| WEB-13 | Security misconfiguration: debug | `app.run(debug=True)` | Trigger unhandled error and inspect traceback |
| WEB-14 | Missing CSP | all responses | No `Content-Security-Policy` |
| WEB-15 | Missing HSTS | all responses | No `Strict-Transport-Security` |
| WEB-16 | Missing X-Frame-Options | all responses | No `X-Frame-Options` |
| WEB-17 | Missing X-Content-Type-Options | all responses | No `X-Content-Type-Options` |
| WEB-18 | Weak/insecure cookie flags | Flask session | Session lacks Secure/HttpOnly/SameSite hardening |
