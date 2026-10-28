using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using SsoServer.Models;
using SsoServer.Services;
using SsoServer.ViewModels;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SsoServer.Controllers;

public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    // ─── Authorization Endpoint ───────────────────────────────────────────────

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenID Connect request cannot be retrieved.");

        // When user submits the consent form
        if (Request.HasFormContentType)
        {
            if (Request.Form.ContainsKey("submit.Deny"))
                return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (Request.Form.ContainsKey("submit.Accept"))
            {
                var acceptResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
                if (!acceptResult.Succeeded)
                    return Challenge(authenticationSchemes: IdentityConstants.ApplicationScheme,
                        properties: new AuthenticationProperties { RedirectUri = Request.PathBase + Request.Path + Request.QueryString });

                var acceptUser = await _userManager.GetUserAsync(acceptResult.Principal)
                    ?? throw new InvalidOperationException("User not found.");
                var acceptApp = await _applicationManager.FindByClientIdAsync(request.ClientId!)
                    ?? throw new InvalidOperationException("Application not found.");

                var acceptAuths = await GetAuthorizationsAsync(acceptUser, acceptApp, request);
                return await IssueSignInAsync(acceptUser, acceptApp, request, acceptAuths, acceptResult.Principal);
            }
        }

        // Check if user is authenticated
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        // کلاینتی که acr_values=gov بفرستد (مثل پنل مدیریت hmu) فقط با ورود از درگاه دولت پذیرفته می‌شود
        bool wantsGov = (request.AcrValues ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Contains(GovAuth.AcrGov);

        if (!result.Succeeded ||
            request.HasPrompt(Prompts.Login) ||
            (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
             DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)))
        {
            if (request.HasPrompt(Prompts.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }));
            }

            var prompt = string.Join(" ", request.GetPrompts().Remove(Prompts.Login));
            var parameters = Request.HasFormContentType
                ? Request.Form.Where(p => p.Key != Parameters.Prompt).ToList()
                : Request.Query.Where(p => p.Key != Parameters.Prompt).ToList();
            parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

            if (wantsGov)
                return RedirectToGov(Request.PathBase + Request.Path + QueryString.Create(parameters));

            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                });
        }

        // جلسه‌ی موجود از درگاه دولت نیست (مثلا ورود با رمز/پیامک) → دوباره از درگاه دولت
        if (wantsGov && result.Principal?.FindFirst(GovAuth.SourceClaim)?.Value != GovAuth.SourceGov)
        {
            if (request.HasPrompt(Prompts.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Government gateway login is required."
                    }));
            }

            var govParameters = (Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                .Where(p => p.Key != Parameters.Prompt).ToList();
            return RedirectToGov(Request.PathBase + Request.Path + QueryString.Create(govParameters));
        }

        var user = await _userManager.GetUserAsync(result.Principal)
            ?? throw new InvalidOperationException("User not found.");

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("Application not found.");

        var authorizations = await GetAuthorizationsAsync(user, application, request);

        switch (await _applicationManager.GetConsentTypeAsync(application))
        {
            case ConsentTypes.External when !authorizations.Any():
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User is not permitted to access this application."
                    }));

            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
            case ConsentTypes.Explicit when authorizations.Any() && !request.HasPrompt(Prompts.Consent):
                return await IssueSignInAsync(user, application, request, authorizations, result.Principal);

            case ConsentTypes.Explicit when request.HasPrompt(Prompts.None):
            case ConsentTypes.Systematic when request.HasPrompt(Prompts.None):
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Interactive consent is required."
                    }));

            default:
                return View(new AuthorizeViewModel
                {
                    ApplicationName = await _applicationManager.GetDisplayNameAsync(application),
                    Scope = request.Scope,
                    ClientId = request.ClientId,
                    RedirectUri = request.RedirectUri,
                    ResponseType = request.ResponseType,
                    State = request.State,
                    Nonce = request.Nonce,
                    CodeChallenge = request.CodeChallenge,
                    CodeChallengeMethod = request.CodeChallengeMethod,
                    ResponseMode = request.ResponseMode
                });
        }
    }

    // ─── Token Endpoint ──────────────────────────────────────────────────────

    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");

        // احراز هویت از طریق OpenIddict — principal حاوی اطلاعات authorization code است
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var userId = result.Principal?.GetClaim(Claims.Subject);
        var user = userId != null ? await _userManager.FindByIdAsync(userId) : null;

        if (user is null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "کاربر یافت نشد یا توکن منقضی شده است."
                }));
        }

        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        principal.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
        principal.SetScopes(result.Principal?.GetScopes() ?? []);
        CopyGovClaims(result.Principal, principal);

        var resources = new List<string>();
        await foreach (var r in _scopeManager.ListResourcesAsync(principal.GetScopes()))
            resources.Add(r);
        principal.SetResources(resources);

        foreach (var claim in principal.Claims)
            claim.SetDestinations(GetDestinations(claim, principal));

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // ─── Logout Endpoint ──────────────────────────────────────────────────────

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }

    // ─── UserInfo Endpoint ────────────────────────────────────────────────────

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = await _userManager.GetUserIdAsync(user)
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = await _userManager.GetEmailAsync(user) ?? string.Empty;
            claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Profile))
        {
            if (!string.IsNullOrEmpty(user.FirstName))
                claims[Claims.GivenName] = user.FirstName;
            if (!string.IsNullOrEmpty(user.LastName))
                claims[Claims.FamilyName] = user.LastName;
            if (!string.IsNullOrEmpty(user.DisplayName))
                claims[Claims.Name] = user.DisplayName;
            if (!string.IsNullOrEmpty(user.NationalId))
                claims["national_id"] = user.NationalId;
            if (!string.IsNullOrEmpty(user.PhoneNumber))
                claims[Claims.PhoneNumber] = user.PhoneNumber;
        }

        if (User.HasScope(Scopes.Roles))
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);

        foreach (var type in GovAuth.ClaimTypes)
        {
            var value = User.FindFirst(type)?.Value;
            if (!string.IsNullOrEmpty(value))
                claims[type] = value;
        }

        return Ok(claims);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private async Task<List<object>> GetAuthorizationsAsync(
        ApplicationUser user, object application, OpenIddictRequest request)
    {
        var list = new List<object>();
        var userId = await _userManager.GetUserIdAsync(user);
        var appId = await _applicationManager.GetIdAsync(application);

        await foreach (var auth in _authorizationManager.FindAsync(
            subject: userId,
            client: appId!,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()))
        {
            list.Add(auth);
        }

        return list;
    }

    private IActionResult RedirectToGov(string authorizeUrl)
        => Redirect(GovAuth.LoginPath + "?returnUrl=" + Uri.EscapeDataString(authorizeUrl));

    // کلیم‌های ورود از درگاه دولت از جلسه (کوکی/کد) به توکن منتقل می‌شوند
    private static void CopyGovClaims(ClaimsPrincipal? source, ClaimsPrincipal target)
    {
        if (source is null) return;
        foreach (var type in GovAuth.ClaimTypes)
        {
            var value = source.FindFirst(type)?.Value;
            if (!string.IsNullOrEmpty(value))
                target.SetClaim(type, value);
        }
    }

    private async Task<IActionResult> IssueSignInAsync(
        ApplicationUser user, object application, OpenIddictRequest request, List<object> authorizations,
        ClaimsPrincipal? sessionPrincipal)
    {
        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        // OpenIddict نیاز به کلیم "sub" دارد که Identity با نام متفاوت ست می‌کند
        principal.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
        CopyGovClaims(sessionPrincipal, principal);

        principal.SetScopes(request.GetScopes());

        var resources = new List<string>();
        await foreach (var r in _scopeManager.ListResourcesAsync(principal.GetScopes()))
            resources.Add(r);
        principal.SetResources(resources);

        var authorization = authorizations.LastOrDefault();
        if (authorization is null)
        {
            authorization = await _authorizationManager.CreateAsync(
                principal: principal,
                subject: await _userManager.GetUserIdAsync(user),
                client: (await _applicationManager.GetIdAsync(application))!,
                type: AuthorizationTypes.Permanent,
                scopes: principal.GetScopes());
        }

        principal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));

        foreach (var claim in principal.Claims)
            claim.SetDestinations(GetDestinations(claim, principal));

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;
                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;
                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;
                yield break;

            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
