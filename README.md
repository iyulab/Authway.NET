# Authway.NET

Single-tenant OpenID Connect identity provider on ASP.NET Core — the .NET edition of Authway. It serves the
same contract as the Go edition (`packages/contract/openapi.yaml`) and is held to it by the same conformance
suite (`packages/conformance`), which is implementation-neutral: it talks to the public surfaces only.

## Building

The server builds inside the Authway repository: the messages it mails are the files of `packages/mail`, which
are built into it, and the build looks for them at `../../../../packages/mail/` from `src/Authway.Server`.
Anywhere else, say where they are: `dotnet build -p:AuthwayMailDir=<path to packages/mail/>`.

```bash
dotnet build
dotnet test       # runs against PostgreSQL and SQL Server in containers
```

## Running

The server reads its settings from configuration (environment variables use `__` for `:`).

| Setting | What it is |
|---|---|
| `ConnectionStrings:Authway` | The database. Required. |
| `Authway:Database:Provider` | `PostgreSql` (default) or `SqlServer`. |
| `Authway:Database:MigrateOnStart` | Apply migrations when the server starts (default `true`). |
| `Authway:Admin:ApiKey` | The administration key, sent as a bearer token to `/api/v1/*` administration calls. Without it nothing is administered (`503 admin_api_not_configured`). |
| `Authway:Ui:Directory` | The build of the sign-in screens, served from the same address. |
| `Authway:Ui:BaseUrl` | The address of the sign-in screens when it is not the one the server is asked at; emailed links point at it. |
| `Authway:Mail:Smtp:Host`, `Port`, `User`, `Password`, `Tls` | The mail server. Without a host no mail is sent, and a call that wants mail says so. |
| `Authway:Mail:From` | The sender's address. |
| `Authway:Limits:SignInPerMinute` | How often one address may answer a sign-in (default 60). |
| `Authway:Audit:RetentionDays` | How long audit entries are kept (default 365, at least 30); the ones past it are removed once a day. |

An installation is one tenant. What it does not offer is said by `GET /api/v1/capabilities`, and a call for
something it does not offer is refused with the code the contract names.

## Conformance

Start the server and an SMTP capture service (MailHog), then run the suite from `packages/conformance` with
`CONFORMANCE_ISSUER`, `CONFORMANCE_API`, `CONFORMANCE_ADMIN_KEY` and `CONFORMANCE_MAIL_API` set; its
`README.md` describes what a provider must offer to be run against. Scenarios that need more than this
installation has (several tenants, other sign-in providers) read the capabilities and are skipped.
