using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Maraki1982.Core.Models.Database;

namespace Maraki1982.Core.DAL.Configuration
{
    public class EmailFolderConfiguration : IEntityTypeConfiguration<EmailFolder>
    {
        public void Configure(EntityTypeBuilder<EmailFolder> builder)
        {
            builder.HasOne(b => b.User);
            builder.HasMany(b => b.Emails);
        }
    }
}
