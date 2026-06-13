# Docker Self-Hosted Migration Plan

## Goal

Provide a fully Docker-based deployment path that can run without Cloudflare Workers and D1:

- A self-hosted controller container serving the dashboard and APIs.
- A SQLite-backed storage adapter replacing D1.
- An agent container that runs the Python proxy engine without systemd.
- Compose/env examples and deployment documentation.

## Boundary

- Keep the original Cloudflare Worker deployment intact.
- Do not refactor the Worker implementation beyond what is required to reuse its embedded dashboard and agent scripts.
- Do not add heavyweight third-party application frameworks.
- Do not implement multi-node orchestration outside the existing agent heartbeat protocol.

## Tasks

- [x] Inspect Worker routes, D1 usage, and agent runtime assumptions.
- [x] Add a self-hosted controller using Python standard library and SQLite.
- [x] Add Dockerfiles, compose file, env example, and agent entrypoint.
- [x] Document the fully Dockerized deployment path.
- [x] Run syntax and smoke checks, then clean temporary files.

## Notes

- The agent container requires host-level networking privileges for OpenVPN/TUN and policy routing.
- The Cloudflare Worker path remains supported through the existing files.
