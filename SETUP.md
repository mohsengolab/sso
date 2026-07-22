# SSO Server - راهنمای راه‌اندازی

## پیش‌نیازها
- .NET 8 SDK
- SQL Server (local یا remote)

## ۱. تنظیم Connection String

در `appsettings.json` رشته اتصال SQL Server را تغییر دهید:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=.;Database=SsoServerDb;Trusted_Connection=True;TrustServerCertificate=True"
}
```

## ۲. ایجاد دیتابیس

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

یا بدون migration (automatic):
جدول‌ها خودکار هنگام اولین اجرا از طریق `EnsureCreated` ساخته می‌شوند.

## ۳. اجرا

```bash
dotnet run
```

سرور روی `https://localhost:5001` اجرا می‌شود.

---

## Endpoint‌ها

| Endpoint | توضیح |
|----------|-------|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /connect/authorize` | Authorization endpoint |
| `POST /connect/token` | Token endpoint |
| `GET /connect/userinfo` | UserInfo endpoint |
| `GET /connect/logout` | Logout endpoint |
| `POST /connect/introspect` | Token introspection |

---

## Client‌های پیش‌فرض (seed شده)

### ۱. web-app (Authorization Code + PKCE)
```
client_id:     web-app
client_secret: web-app-secret-CHANGE-IN-PRODUCTION
grant_type:    authorization_code
redirect_uri:  https://oauth.pstmn.io/v1/callback
scopes:        openid profile email roles api
```

### ۲. m2m-client (Client Credentials)
```
client_id:     m2m-client
client_secret: m2m-secret-CHANGE-IN-PRODUCTION
grant_type:    client_credentials
scopes:        api
```

---

## تست با Postman

1. مجموعه OAuth2 جدید بساز
2. Authorization URL: `https://localhost:5001/connect/authorize`
3. Token URL: `https://localhost:5001/connect/token`
4. Client ID: `web-app`
5. Client Secret: `web-app-secret-CHANGE-IN-PRODUCTION`
6. Scope: `openid profile email`
7. Code Challenge Method: `SHA-256`

---

## اتصال Resource Server (API دیگر) به این SSO

در پروژه API دیگر:

```csharp
builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        options.SetIssuer("https://localhost:5001/");
        options.AddAudiences("api");
        options.UseIntrospection()
               .SetClientId("resource-server")
               .SetClientSecret("your-secret");
        options.UseSystemNetHttp();
        options.UseAspNetCore();
    });
```

---

## Production - کلید RSA واقعی

```bash
# ایجاد certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
openssl pkcs12 -export -out signing.pfx -inkey key.pem -in cert.pem
```

در `appsettings.json` (production):
```json
"Jwt": {
  "CertPath": "/path/to/signing.pfx",
  "CertPassword": "your-password"
}
```
