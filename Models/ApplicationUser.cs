using Microsoft.AspNetCore.Identity;

namespace SsoServer.Models;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? DisplayName { get; set; }
    public string? NationalId { get; set; }
}
