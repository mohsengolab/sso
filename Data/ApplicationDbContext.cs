using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SsoServer.Models;

namespace SsoServer.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<VerifyMobile> VerifyMobiles { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<VerifyMobile>(e =>
        {
            e.ToTable("VerifyMobile");
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.PhoneNumber);
        });
    }
}
