# bff-oidc

BFF en Go para centralizar la autenticación OIDC con TinyAuth usando Authorization Code + PKCE.

## Endpoints

- `GET /healthz`
- `GET /auth/login`
- `GET /auth/callback?code&state`
- `GET /auth/me`
- `POST /auth/refresh`
- `POST /auth/logout`

## Configuración requerida

```bash
APP_ADDR=:8080
APP_BASE_URL=https://bff.tu-dominio.com
FRONTEND_URL=https://app.tu-dominio.com
OIDC_ISSUER=https://auth.tu-dominio.com
OIDC_AUTH_URL=https://auth.tu-dominio.com/authorize
OIDC_TOKEN_URL=https://auth.tu-dominio.com/api/oidc/token
OIDC_USERINFO_URL=https://auth.tu-dominio.com/api/oidc/userinfo
OIDC_CLIENT_ID=bff-oidc
OIDC_CLIENT_SECRET=super-secret
OIDC_REDIRECT_URL=https://bff.tu-dominio.com/auth/callback
OIDC_SCOPES="openid profile email offline_access"
SESSION_SECRET=un-secreto-largo-de-al-menos-32-bytes
COOKIE_DOMAIN=.tu-dominio.com
COOKIE_SECURE=true
```

## Comportamiento

- `state`, `nonce` y `code_verifier` se guardan en cookies temporales firmadas.
- La sesión se guarda en memoria del proceso y la cookie de sesión es `HttpOnly`, `Secure` y `SameSite=Lax`.
- El callback valida `state`, canjea el `code`, valida `nonce` y redirige a `FRONTEND_URL/dashboard`.
- CORS queda restringido a `FRONTEND_URL`.
