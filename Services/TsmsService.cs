using Microsoft.Extensions.Options;

namespace SsoServer.Services;

public class TsmsSettings
{
    public string BaseUrl { get; set; } = "http://tsms.ir/url/tsmshttp.php";
    public string From { get; set; } = "3000101018";
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class TsmsService : ISmsService
{
    private readonly TsmsSettings _settings;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<TsmsService> _logger;

    public TsmsService(
        IOptions<TsmsSettings> settings,
        IHttpClientFactory httpClientFactory,
        ILogger<TsmsService> logger)
    {
        _settings = settings.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task SendAsync(string phoneNumber, string message)
    {
        var url = $"{_settings.BaseUrl}?from={_settings.From}" +
                  $"&to={phoneNumber}" +
                  $"&username={_settings.Username}" +
                  $"&password={_settings.Password}" +
                  $"&message={Uri.EscapeDataString(message)}";

        try
        {
            var client = _httpClientFactory.CreateClient("tsms");
            var response = await client.GetAsync(url);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadAsStringAsync();
            _logger.LogInformation("SMS sent to {Phone} | Result: {Result}", phoneNumber, result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send SMS to {Phone}", phoneNumber);
            throw;
        }
    }
}
