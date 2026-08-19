# Invoices API Implementation Plan

**Goal:** Add an org-scoped invoices HTTP API.

**Architecture:** Next.js route handlers behind session auth. Stripe webhooks verified with the signing secret.

**Tech Stack:** Next.js, Stripe, Postgres

### Task 1: Authenticated endpoint

- [ ] Add a POST /api/invoices endpoint
- [ ] Require a session cookie and verify `invoice.orgId === session.orgId` before write
- [ ] Add a Stripe webhook; verify `stripe.webhooks.constructEvent` before any mutation
- [ ] Do not fetch URLs from the request body

## Security Check

old contents that must be replaced
