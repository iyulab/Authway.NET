namespace Authway.Server.Tests;

public sealed class PostgresServerTests(PostgresServerFixture fixture) : ServerTests(fixture), IClassFixture<PostgresServerFixture>;
