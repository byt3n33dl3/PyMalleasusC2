using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Maraki1982.Core.Models.Database;

namespace Maraki1982.Core.DAL.Configuration
{
    public class DriveConfiguration : IEntityTypeConfiguration<Drive>
    {
        public void Configure(EntityTypeBuilder<Drive> builder)
        {
            builder.HasOne(b => b.User);
            builder.HasMany(b => b.Folders);
        }
    }
}
