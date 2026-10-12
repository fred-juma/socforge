# SocForge

SOCForge is a modular, vendor-neutral cybersecurity operations platform that integrates security tools, normalizes alerts into a common data model, and correlates fragmented signals into actionable incidents. It supports pluggable enrichment, triage, and response adapters, enabling AI-assisted investigation and coordinated security operations across heterogeneous environments.

SOCForge follows a hexagonal architecture: domain logic resides in `core/`, external technology integrations are implemented in `adapters/`, canonical data contracts are maintained in `schemas/`, and automated tests in `tests/` validate functionality, integration compatibility, and tenant isolation.

## Run

docker compose up --build