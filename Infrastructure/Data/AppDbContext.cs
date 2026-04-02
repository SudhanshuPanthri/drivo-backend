using drivo_backend.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace drivo_backend.Infrastructure.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options){}
    public DbSet<User> Users {get;set;}
    public DbSet<RefreshToken> RefreshTokens {get;set;}

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(entity =>
          {
              entity.HasKey(e => e.Id);
              entity.HasIndex(e => e.Email).IsUnique();
              entity.Property(e => e.Email).IsRequired().HasMaxLength(255);
              entity.Property(e => e.FirstName).HasMaxLength(100);
              entity.Property(e => e.LastName).HasMaxLength(100);
              entity.Property(e => e.PasswordHash).IsRequired();
          });

          modelBuilder.Entity<RefreshToken>(entity =>
          {
              entity.HasKey(e => e.Id);
              entity.HasIndex(e => e.Token);
              entity.Property(e => e.Token).IsRequired();
              entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
          });
    }
}