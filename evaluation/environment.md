# Environment and seed information

Final results correspond to tag `cs5903-final-2026`.

## Fill in for the final run

| Item | Value |
| --- | --- |
| Commit SHA | TODO (`git rev-parse HEAD`) |
| Run ID and timestamp | TODO (`summary.run_id` and `summary.date` in `test/results/results.json`) |
| CPU | TODO (`lscpu`) |
| RAM | TODO (`free -h`) |
| OS | TODO (`uname -a`) |
| Docker | TODO (`docker --version`) |
| Docker Compose | TODO (`docker compose version`) |
| OpenFGA version and image digest | TODO (`docker compose images`; `docker inspect --format '{{.Image}}' iam_openfga`; `docker exec iam_openfga /openfga version`) |
| Python and pytest | TODO (`python3 --version`; `pip list \| grep -i -E "pytest\|requests\|psycopg2\|beautifulsoup4"`) |

## Pinned by the repository

| Component | Version | Source |
| --- | --- | --- |
| Keycloak (`keycloak` and `acme-idp` services) | 26.0 | `docker-compose.yml`: `quay.io/keycloak/keycloak:26.0` |
| PostgreSQL | 16 | `docker-compose.yml`: `postgres:16-alpine` |
| Gateway runtime | Node.js 20 | `gateway/Dockerfile`: `node:20-alpine` |
| OpenFGA | not pinned | `docker-compose.yml`: `openfga/openfga:latest`. Record the digest above, or pin a version tag before the final run. |
| Test dependencies | `pytest>=8`, `requests>=2.31`, `psycopg2-binary>=2.9`, `beautifulsoup4>=4.12` | `test/requirements.txt` |

## Seed and determinism

- The seed (`gateway/scripts/seed.js`) is deterministic and contains no random values. See `docs/workload.md` for its contents.
- No scenario samples randomly, so there is no random seed. The only random value is the per-run suffix (`RUN`) in test tenant names.
- OpenFGA uses the in-memory datastore. A plain restart wipes all tuples while the gateway keeps its old store id. The test pre-flight check detects this and stops with instructions (`docker compose down`, then `docker compose up -d`).
- Timing noise: the outbox worker polls every 1 s, so propagation delay is about 0 to 1 s plus request time. Latency figures depend on the host, so they are only comparable within one environment.
