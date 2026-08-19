# Invoices API Implementation Plan

**Goal:** Add a public invoices HTTP API.

**Architecture:** A Next.js route handler accepts Stripe webhooks and a REST API for listing invoices.

**Tech Stack:** Next.js, Stripe, Postgres

### Task 1: Public endpoint

- [ ] Add a POST /api/invoices endpoint that creates an invoice from the JSON body
- [ ] Add a Stripe webhook that marks invoices paid
- [ ] fetch the user-provided URL on the server to download the PDF
