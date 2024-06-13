using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Maraki1982.Core.Models.Database;

namespace Maraki1982.Core.DAL.Configuration
{
    public class EmailConfiguration : IEntityTypeConfiguration<Email>
    {
        public void Configure(EntityTypeBuilder<Email> builder)
        {
            builder.HasOne(b => b.EmailFolder);
        }
    }
}
