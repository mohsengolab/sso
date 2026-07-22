using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SsoServer.Models;
using SsoServer.Services;

namespace SsoServer.Controllers;

[Route("external/msrt")]
public class ExternalAuthController : Controller
{
    private const string StateTempDataKey = "msrt_state";
    private const string ReturnUrlTempDataKey = "msrt_returnurl";

    private readonly MsrtSettings _settings;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ExternalAuthController> _logger;

    public ExternalAuthController(
        IOptions<MsrtSettings> settings,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IHttpClientFactory httpClientFactory,
        ILogger<ExternalAuthController> logger)
    {
        _settings = settings.Value;
        _userManager = userManager;
        _signInManager = signInManager;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    // ─── مرحله ۱: ریدایرکت به درگاه وزارت علوم ────────────────────────────────

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        var state = Guid.NewGuid().ToString("N");
        TempData[StateTempDataKey] = state;
        TempData[ReturnUrlTempDataKey] = returnUrl;

        var authUrl = _settings.AuthorizeEndpoint
            + "?response_type=code"
            + "&client_id=" + Uri.EscapeDataString(_settings.ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(_settings.RedirectUri)
            + "&scope=" + Uri.EscapeDataString("openid profile")
            + "&state=" + Uri.EscapeDataString(state);

        return Redirect(authUrl);
    }

    // ─── مرحله ۲: بازگشت از درگاه وزارت علوم ──────────────────────────────────

    [HttpGet("callback")]
    public async Task<IActionResult> Callback(string? code, string? state)
    {
        var savedState = TempData[StateTempDataKey] as string;
        var returnUrl = TempData[ReturnUrlTempDataKey] as string;

        if (string.IsNullOrEmpty(code))
            return RedirectToAction("Login", "Account", new { returnUrl, error = "msrt_nocode" });

        if (string.IsNullOrEmpty(state) || string.IsNullOrEmpty(savedState) || state != savedState)
        {
            _logger.LogWarning("درخواست بازگشتی MSRT با state نامعتبر رد شد.");
            return RedirectToAction("Login", "Account", new { returnUrl, error = "msrt_state" });
        }

        var accessToken = await ExchangeCodeForTokenAsync(code);
        if (string.IsNullOrEmpty(accessToken))
            return RedirectToAction("Login", "Account", new { returnUrl, error = "msrt_token" });

        var info = await GetUserInfoAsync(accessToken);
        if (info is null || string.IsNullOrEmpty(info.NationalId))
            return RedirectToAction("Login", "Account", new { returnUrl, error = "msrt_userinfo" });

        var user = await _userManager.Users.FirstOrDefaultAsync(u => u.NationalId == info.NationalId);
        if (user is null)
        {
            user = new ApplicationUser
            {
                UserName = info.NationalId,
                NationalId = info.NationalId,
                FirstName = info.FirstName,
                LastName = info.LastName,
                DisplayName = $"{info.FirstName} {info.LastName}".Trim(),
                PhoneNumber = info.Mobile,
                PhoneNumberConfirmed = !string.IsNullOrEmpty(info.Mobile),
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogError("ساخت کاربر از روی اطلاعات MSRT ناموفق بود: {Errors}",
                    string.Join(", ", result.Errors.Select(e => e.Description)));
                return RedirectToAction("Login", "Account", new { returnUrl, error = "msrt_create" });
            }
        }

        await _signInManager.SignInAsync(user, isPersistent: false);
        _logger.LogInformation("کاربر با کد ملی {NationalId} از طریق درگاه دولت وارد شد", info.NationalId);

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            return Redirect(returnUrl);

        return RedirectToAction("Index", "Home");
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private async Task<string?> ExchangeCodeForTokenAsync(string code)
    {
        var client = _httpClientFactory.CreateClient("msrt");

        var pairs = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", _settings.RedirectUri),
            new("client_id", _settings.ClientId),
            new("client_secret", _settings.ClientSecret)
        };

        try
        {
            var response = await client.PostAsync(_settings.TokenEndpoint, new FormUrlEncodedContent(pairs));
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("درخواست توکن به MSRT با کد {Status} برگشت", response.StatusCode);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync();
            var token = JsonSerializer.Deserialize<MsrtTokenResponse>(json, JsonOptions);
            return token?.AccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "خطا در تبادل کد با MSRT");
            return null;
        }
    }

    private async Task<GovUserInfo?> GetUserInfoAsync(string accessToken)
    {
        var client = _httpClientFactory.CreateClient("msrt");
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        try
        {
            var response = await client.GetAsync(_settings.UserInfoEndpoint);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("درخواست userinfo به MSRT با کد {Status} برگشت", response.StatusCode);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync();
            var wrapper = JsonSerializer.Deserialize<GovUserInfoWrapper>(json, JsonOptions);
            return wrapper is { IsSuccess: true } ? wrapper.Data : null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "خطا در دریافت اطلاعات کاربر از MSRT");
            return null;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private class MsrtTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }
    }

    private class GovUserInfoWrapper
    {
        public GovUserInfo? Data { get; set; }
        public bool IsSuccess { get; set; }
        public string? Message { get; set; }
    }

    private class GovUserInfo
    {
        public string? Sub { get; set; }
        public string? NationalId { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? FatherName { get; set; }
        public string? Mobile { get; set; }
        public string? Gender { get; set; }
        public string? BirthDateShamsi { get; set; }
    }
}
