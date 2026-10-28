using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using SsoServer.Data;
using SsoServer.Models;
using SsoServer.Services;
using SsoServer.Workers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// ─── Database ─────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

// ─── Identity ─────────────────────────────────────────────────────────────────
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.SignIn.RequireConfirmedAccount = false;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
});

// ─── OpenIddict (OAuth2 / OpenID Connect Server with RS256) ───────────────────
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        // Endpoints
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetUserinfoEndpointUris("/connect/userinfo")
               .SetLogoutEndpointUris("/connect/logout")
               .SetIntrospectionEndpointUris("/connect/introspect");

        // Supported flows
        options.AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange()   // PKCE اجباری
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow();

        // RS256 signing key — PFX cert preferred, RSA file-keys as fallback
        var certPath = builder.Configuration["Jwt:CertPath"];
        bool certLoaded = false;
        if (!string.IsNullOrEmpty(certPath))
        {
            if (!Path.IsPathRooted(certPath))
                certPath = Path.Combine(builder.Environment.ContentRootPath, certPath);

            if (File.Exists(certPath))
            {
                try
                {
                    var certPassword = builder.Configuration["Jwt:CertPassword"] ?? "";
                    var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                        certPath, certPassword,
                        System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.EphemeralKeySet);
                    options.AddSigningCertificate(cert)
                           .AddEncryptionCertificate(cert);
                    certLoaded = true;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[SSO] Could not load cert from {certPath}: {ex.Message}");
                }
            }
        }
        if (!certLoaded)
        {
            // fallback: کلید RSA ذخیره‌شده در فایل — بدون نیاز به Certificate Store
            var keysDir = Path.Combine(builder.Environment.ContentRootPath, "keys");
            Directory.CreateDirectory(keysDir);

            options.AddSigningKey(LoadOrCreateRsaKey(Path.Combine(keysDir, "signing.key")));
            options.AddEncryptionKey(LoadOrCreateRsaKey(Path.Combine(keysDir, "encryption.key")));
        }

        // Access token به صورت JWT خام (بدون رمزنگاری اضافی) - برای resource server‌ها راحت‌تر
        options.DisableAccessTokenEncryption();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserinfoEndpointPassthrough()
               .EnableLogoutEndpointPassthrough()
               .EnableStatusCodePagesIntegration();

        // Scopes قابل درخواست
        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles,
            "api"
        );
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// ─── SMS Service (OTP) ───────────────────────────────────────────────────────
builder.Services.Configure<TsmsSettings>(builder.Configuration.GetSection("Tsms"));
builder.Services.AddHttpClient("tsms");
builder.Services.AddScoped<ISmsService, TsmsService>();

// ─── ورود از طریق درگاه وزارت علوم (MSRT) ────────────────────────────────────
builder.Services.Configure<MsrtSettings>(builder.Configuration.GetSection("Msrt"));
builder.Services.AddHttpClient("msrt");

// seed کردن client‌های اولیه هنگام startup
builder.Services.AddHostedService<ClientSeeder>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static Microsoft.IdentityModel.Tokens.RsaSecurityKey LoadOrCreateRsaKey(string path)
{
    var rsa = System.Security.Cryptography.RSA.Create(2048);
    if (File.Exists(path))
    {
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(File.ReadAllText(path)), out _);
    }
    else
    {
        File.WriteAllText(path, Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
    }
    return new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);
}
