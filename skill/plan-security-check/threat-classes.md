# Threat classes for plan review

Use matcher slugs as `vulnSlug`. If nothing fits, use `other-<kebab>`.

## Always-on (plans)

| slug | Ask of the plan |
|---|---|
| `auth-boundary` | Every new ingress names the authn primitive and the authz check (who can act on whose data). Middleware-only is not enough for server actions / POST handlers. |
| `injection-sql` | Queries use bound parameters. No f-string / concatenated SQL. |
| `ssrf` | Server-side fetch allowlists scheme/host. No user-controlled URLs. |
| `path-traversal` | Uploads land in a fixed directory with generated names; user path segments are not joined. |
| `xss` | User HTML/Markdown is sanitized or not rendered as HTML. |
| `secrets` | Secrets live in env vars, never in source, client bundles, or committed `.env`. |
| `command-injection` | No shell. If a binary must run, argv is a literal list. |
| `insecure-deser` | No `pickle.loads` / `yaml.load` / `unserialize` on untrusted bytes. |
| `cors-wildcard` | Credentialed APIs name explicit origins. |
| `webhook-unverified` | Inbound webhooks verify provider signatures before mutations. |
| `mass-assignment` | Persistence allowlists fields; request bodies are not spread into updates. |
| `crypto-weak` | Passwords use argon2/bcrypt/scrypt; JWT algorithms are explicit and exclude `none`. |
| `agent-tool-egress` | Agent tools cannot exec arbitrary shell or fetch arbitrary URLs. |
| `ci-untrusted-checkout` | Jobs that run PR code do not get `write` or secrets. Split analyze vs comment jobs. |

## Per-tech highlights (inject the matching bullets into process)

### nextjs
- `middleware.ts` is not authentication for Server Actions or Route Handlers.
- Server Actions are public POSTs; they need the same authz as a REST route.
- `searchParams` and `x-forwarded-*` are attacker-controlled.

### express
- Middleware order matters; a route registered before `auth` is public.
- `express.static` and `res.sendFile` are traversal-prone.

### fastapi
- Missing `Depends(get_current_user)` (or equivalent) means the route is public.
- `response_model` omission leaks internal fields.

### django
- `@csrf_exempt` on writes, f-string SQL, `mark_safe`, missing `permission_classes`.

### rails
- `skip_before_action :authenticate_user!`, `html_safe`, strong-params bypass.

### go
- Router middleware does not automatically wrap sub-mounts. `URLParam` is untrusted.

### github-actions
- `pull_request` + `secrets.*` + `contents: write` is a combo to BLOCK.
- Pin actions to SHAs in production plans.

### agent
- Treat tool schemas as an API surface. Same SSRF, injection, and auth rules apply.

<!--
Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
This file has been modified from its original form.
-->
