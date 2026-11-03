namespace Authway.Server.Tests;

public sealed class SqlServerServerTests(SqlServerServerFixture fixture) : ServerTests(fixture), IClassFixture<SqlServerServerFixture>;
