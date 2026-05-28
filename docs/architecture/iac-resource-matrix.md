# IaC Resource Matrix (Terraform)

## Goal
Define infrastructure resources required by environment and ownership tier.

## Environments

| Tag | Description |
|---|---|
| `dev` | Local/experimental; reduced redundancy |
| `stage` | Pre-production soak; near-prod configuration |
| `prod` | Full HA, Multi-AZ, compliance-enforced |

---

## Core AWS Resources

| Domain | Resource | Dev | Stage | Prod | Notes |
|---|---|:---:|:---:|:---:|---|
| Network | VPC + subnets + route tables | ✅ | ✅ | ✅ | Multi-AZ required for prod |
| Security | Security Groups + NACL rules | ✅ | ✅ | ✅ | Least privilege |
| Compute | ECS Cluster + Fargate Services | ✅ | ✅ | ✅ | API, ETL jobs, predictor |
| Registry | ECR Repositories | ✅ | ✅ | ✅ | Image scanning enabled |
| Load Balancing | ALB + target groups + listeners | ✅ | ✅ | ✅ | TLS termination |
| Database | RDS PostgreSQL (pgvector) | ✅ | ✅ | ✅ | Multi-AZ in prod |
| Cache | ElastiCache Redis | Optional | ✅ | ✅ | Sessions/rate-limit/cache |
| Secrets | AWS Secrets Manager | ✅ | ✅ | ✅ | Connector/API credentials |
| Encryption | KMS CMKs | ✅ | ✅ | ✅ | At-rest encryption |
| DNS | Route53 records | Optional | ✅ | ✅ | Internal/external split |
| Monitoring | CloudWatch logs/alarms/dashboards | ✅ | ✅ | ✅ | SLO and budget alarms |
| Backup | RDS snapshots + S3 backup bucket | ✅ | ✅ | ✅ | Retention policies enforced |
| Identity | IAM roles/policies (task/execution) | ✅ | ✅ | ✅ | Scoped per service |

---

## Connector Secrets Required

The following credentials must be provisioned in Secrets Manager before deployment:

- ServiceNow API credentials (read + conditional write)
- Grafana API token
- PagerDuty API token + routing keys
- OIDC client config (Azure AD/Okta)
- Optional: Bedrock/OpenAI API key

---

## Minimum Terraform Modules

```
modules/
├── network          # VPC, subnets, route tables, NACLs
├── security         # Security groups, WAF
├── ecr              # Container registry + scan policies
├── ecs              # Cluster, task definitions, services
├── alb              # Load balancer, listeners, target groups
├── rds_pgvector     # PostgreSQL + pgvector extension
├── redis            # ElastiCache cluster
├── secrets          # Secrets Manager entries
├── kms              # Customer-managed keys
├── monitoring       # CloudWatch alarms, dashboards, budgets
└── backup           # RDS snapshot + S3 backup lifecycle
```

---

## Deployment Order (Dependency-Safe)

1. `network`
2. `security`
3. `kms` → `secrets`
4. `rds_pgvector` → `redis`
5. `ecr` → `ecs`
6. `alb`
7. `monitoring` → `backup`
