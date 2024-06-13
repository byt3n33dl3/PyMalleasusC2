using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maraki1982.Core.DAL.Configuration
{
    public class IdentityUserRoleConfiguration : IEntityTypeConfiguration<IdentityUserRole<string>>
    {
        private readonly string _roleId;
        private readonly string _userId;

        public IdentityUserRoleConfiguration(string roleId, string userId) : base()
        {
            _roleId = roleId;
            _userId = userId;
        }

        public void Configure(EntityTypeBuilder<IdentityUserRole<string>> builder)
        {
            builder.HasData(new IdentityUserRole<string>
            {
                RoleId = _roleId,
                UserId = _userId
            });
        }
    }
}
