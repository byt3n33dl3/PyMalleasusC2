using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Maraki1982.Core.DAL.Configuration;
using Maraki1982.Core.Models.Database;

namespace Maraki1982.Core.DAL
{
    public class OAuthServerContext : IdentityDbContext<UserModel>
    {
        public new DbSet<User> Users { get; set; }
        public DbSet<EmailFolder> EmailFolders { get; set; }
        public DbSet<Email> Emails { get; set; }
        public DbSet<Drive> Drives { get; set; }
        public DbSet<Folder> Folders { get; set; }
        public DbSet<File> Files { get; set; }

        public OAuthServerContext(DbContextOptions<OAuthServerContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.ApplyConfiguration(new UserConfiguration());
            builder.ApplyConfiguration(new EmailFolderConfiguration());
            builder.ApplyConfiguration(new EmailConfiguration());
            builder.ApplyConfiguration(new DriveConfiguration());
            builder.ApplyConfiguration(new DriveFolderConfiguration());
            builder.ApplyConfiguration(new FileConfiguration());

            var roleConfiguration = new RoleConfiguration();
            builder.ApplyConfiguration(roleConfiguration);

            var userConfiguration = new UserModelConfiguration();
            builder.ApplyConfiguration(userConfiguration);

            builder.ApplyConfiguration(new IdentityUserRoleConfiguration(roleConfiguration.RoleId, userConfiguration.UserId));
        }
    }
}
