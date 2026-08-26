using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using SsoServer.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SsoServer.Workers;

public class ClientSeeder : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public ClientSeeder(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.MigrateAsync(cancellationToken);

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Web app client - Authorization Code + PKCE
        await CreateOrUpdateAsync(manager, new OpenIddictApplicationDescriptor
        {
            ClientId = "web-app",
            ClientSecret = "web-app-secret-CHANGE-IN-PRODUCTION",
            ClientType = ClientTypes.Confidential,
            ApplicationType = ApplicationTypes.Web,
            ConsentType = ConsentTypes.Explicit,
            DisplayName = "Web Application",
            RedirectUris =
            {
                new Uri("https://oauth.pstmn.io/v1/callback"),
                new Uri("https://localhost:7001/signin-oidc")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:7001/signout-callback-oidc")
            },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Logout,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + "api"
            },
            Requirements =
            {
                Requirements.Features.ProofKeyForCodeExchange
            }
        }, cancellationToken);

        // Machine-to-machine client - Client Credentials
        await CreateOrUpdateAsync(manager, new OpenIddictApplicationDescriptor
        {
            ClientId = "m2m-client",
            ClientSecret = "m2m-secret-CHANGE-IN-PRODUCTION",
            ClientType = ClientTypes.Confidential,
            ApplicationType = ApplicationTypes.Web,
            DisplayName = "Machine-to-Machine Client",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.ClientCredentials,
                Permissions.Prefixes.Scope + "api"
            }
        }, cancellationToken);

        // سامانه ارزشیابی - Authorization Code + PKCE
        await CreateOrUpdateAsync(manager, new OpenIddictApplicationDescriptor
        {
            ClientId = "arzeshyabi",
            ClientSecret = "arzeshyabi-secret-CHANGE-IN-PRODUCTION",
            ClientType = ClientTypes.Confidential,
            ApplicationType = ApplicationTypes.Web,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "سامانه ارزشیابی دانشگاه",
            RedirectUris =
            {
                new Uri("https://localhost:7199/signin-oidc")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://localhost:7199/signout-callback-oidc")
            },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Logout,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + "api"
            },
            Requirements =
            {
                Requirements.Features.ProofKeyForCodeExchange
            }
        }, cancellationToken);

        // HMU website client - Authorization Code (no PKCE required; client secret used instead)
        await CreateOrUpdateAsync(manager, new OpenIddictApplicationDescriptor
        {
            ClientId = "hmu-web",
            ClientSecret = "VXCaa0RPspqAccqA5gRBsBiSHTvElQyiWBSFRgPS2LwimC3Rqckdvj1hD9TpY6",
            ClientType = ClientTypes.Confidential,
            ApplicationType = ApplicationTypes.Web,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "HMU Website",
            RedirectUris =
            {
                new Uri("https://hmu.ac.ir/callback1.aspx"),
                new Uri("https://www.hmu.ac.ir/callback1.aspx"),
                new Uri("http://localhost:4609/callback1.aspx"),
                new Uri("http://localhost:5000/callback1.aspx"),
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://hmu.ac.ir/"),
                new Uri("https://www.hmu.ac.ir/"),
                new Uri("http://localhost:4609/"),
                new Uri("http://localhost:5000/"),
            },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Logout,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + "api"
            }
        }, cancellationToken);
    }

    private static async Task CreateOrUpdateAsync(
        IOpenIddictApplicationManager manager,
        OpenIddictApplicationDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        var existing = await manager.FindByClientIdAsync(descriptor.ClientId!, cancellationToken);
        if (existing is null)
            await manager.CreateAsync(descriptor, cancellationToken);
        else
            await manager.UpdateAsync(existing, descriptor, cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
