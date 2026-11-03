using Authway.Data;
using Microsoft.EntityFrameworkCore;

namespace Authway.Data.Tests;

/// <summary>An empty database of one provider, started for a test class.</summary>
public interface IDatabaseFixture
{
    DbContextOptions<AuthwayDbContext> Options();
}
