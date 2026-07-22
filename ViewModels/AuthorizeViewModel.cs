namespace SsoServer.ViewModels;

public class AuthorizeViewModel
{
    public string? ApplicationName { get; set; }
    public string? Scope { get; set; }
    public string? ClientId { get; set; }
    public string? RedirectUri { get; set; }
    public string? ResponseType { get; set; }
    public string? State { get; set; }
    public string? Nonce { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public string? ResponseMode { get; set; }
}
