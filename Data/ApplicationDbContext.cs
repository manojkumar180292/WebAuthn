using Microsoft.EntityFrameworkCore;
using WebAuthnDemo.Models;

namespace WebAuthnDemo.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        // DbSets for each table
        public DbSet<User> Users { get; set; }
        public DbSet<WebAuthnCredential> WebAuthnCredentials { get; set; }

        // OnModelCreating to configure relationships if necessary
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure the foreign key relationship between User and WebAuthnCredential
            modelBuilder.Entity<WebAuthnCredential>()
                .HasOne(w => w.User)
                .WithMany(u => u.WebAuthnCredentials)
                .HasForeignKey(w => w.UserId)
                .OnDelete(DeleteBehavior.Cascade); // Delete credentials when user is deleted
        }
    }
}