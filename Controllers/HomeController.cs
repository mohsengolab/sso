using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace SsoServer.Controllers;

public class HomeController : Controller
{
    private readonly IOpenIddictApplicationManager _appManager;

    public HomeController(IOpenIddictApplicationManager appManager)
        => _appManager = appManager;

    public async Task<IActionResult> Index()
    {
        var apps = new List<AppCard>();

        await foreach (var app in _appManager.ListAsync())
        {
            var clientId     = await _appManager.GetClientIdAsync(app) ?? "";
            var displayName  = await _appManager.GetDisplayNameAsync(app) ?? clientId;
            var redirectUris = await _appManager.GetRedirectUrisAsync(app);

            // آدرس خانه: اولین redirect URI بدون path
            string? homeUrl = null;
            if (redirectUris.Length > 0)
            {
                if (Uri.TryCreate(redirectUris[0], UriKind.Absolute, out var uri))
                    homeUrl = $"{uri.Scheme}://{uri.Host}{(uri.IsDefaultPort ? "" : $":{uri.Port}")}";
            }

            apps.Add(new AppCard
            {
                ClientId    = clientId,
                DisplayName = displayName,
                HomeUrl     = GetHomeUrl(clientId) ?? homeUrl,
                Icon        = GetIcon(clientId),
                Description = GetDescription(clientId),
                Color       = GetColor(clientId)
            });
        }

        // کلاینت m2m را نشان نده (فقط سرور-به-سرور است)
        apps = apps.Where(a => a.ClientId != "m2m-client").ToList();

        return View(apps);
    }

    // ─── اطلاعات سفارشی هر کلاینت ───────────────────────────────────────────

    private static string? GetHomeUrl(string clientId) => clientId switch
    {
        "hmu-web" => "https://hmu.ac.ir/profile",
        _         => null
    };

    private static string GetIcon(string clientId) => clientId switch
    {
        "hmu-web" => "🏛",
        "web-app" => "🌐",
        _         => "🔗"
    };

    private static string GetDescription(string clientId) => clientId switch
    {
        "hmu-web" => "پورتال اصلی دانشگاه حضرت معصومه (س) — مدیریت پروفایل، اخبار و خدمات دانشگاهی",
        "web-app" => "نرم‌افزار وب عمومی",
        _         => "سامانه متصل به SSO"
    };

    private static string GetColor(string clientId) => clientId switch
    {
        "hmu-web" => "#1a5c3a",
        "web-app" => "#1e40af",
        _         => "#6b7280"
    };
}

public class AppCard
{
    public string ClientId    { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string? HomeUrl    { get; set; }
    public string Icon        { get; set; } = "🔗";
    public string Description { get; set; } = "";
    public string Color       { get; set; } = "#6b7280";
}
