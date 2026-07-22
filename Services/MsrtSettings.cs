namespace SsoServer.Services;

public class MsrtSettings
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string AuthorizeEndpoint { get; set; } = "https://usw.msrt.ir/oauth2/authorize";
    public string TokenEndpoint { get; set; } = "https://usw.msrt.ir/oauth2/token";
    public string UserInfoEndpoint { get; set; } = "https://usw.msrt.ir/oauth2/userinfo";
    public string RedirectUri { get; set; } = string.Empty;
}
