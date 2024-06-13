using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Maraki1982.Core.Models.Database;

namespace Maraki1982.Core.DAL.Configuration
{
    public class DriveFolderConfiguration : IEntityTypeConfiguration<Folder>
    {
        public void Configure(EntityTypeBuilder<Folder> builder)
        {
            builder.HasOne(b => b.Drive);
            builder.HasMany(b => b.Files);
        }
    }
}
