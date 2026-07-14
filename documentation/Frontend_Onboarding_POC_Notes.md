# Frontend Onboarding POC Notes

## Purpose

This note captures the onboarding API changes implemented for frontend integration and demo stability.

## Problem Statement

The frontend onboarding flow needed a clear multi-step API process:

1. Upload dependency file and generate SBOM.
2. Check SBOM validity and quality before SW360 sync.
3. Sync accepted SBOM to SW360.

Additionally, users needed:

1. A way to check externally uploaded SBOM files (without generation).
2. A way to download component-only SBOM details in JSON.
3. Better quality explanations that are understandable to non-SBOM experts.

## Why app.py is used

`app.py` is used as the single FastAPI entrypoint for this POC because:

1. Frontend proxy and demo runtime are already wired to this entrypoint on port 8000.
2. Keeping one active entrypoint simplifies onboarding flow, troubleshooting, and handover.
3. API routes, job tracking, and response shaping are centralized for predictable behavior.

## Implemented API Flow

### 1) Generate SBOM

- Endpoint: `POST /api/sbom/generate`
- Input: ecosystem + dependency file
- Output: jobId for polling

### 2) Check SBOM (separate step)

- Endpoint: `POST /api/sbom/check`
- Supports OR mode:
  - generated SBOM via `sbom_job_id`
  - uploaded SBOM via file upload (`file` or `sbomFile`)
- Output includes:
  - CycloneDX validation result
  - quality summary
  - user-friendly interpretation (meaning, hint, thresholds, reasons, recommendations)
  - reference to `documentation/SBOM_Quality.md`

### 3) Sync to SW360

- Endpoint: `POST /api/sbom/sync`
- Uses checked/generated SBOM plus SW360 credentials and project info

### 4) Download component-only SBOM JSON

- Endpoint: `GET /api/sbom/download/{job_id}`
- Returns component-focused JSON download for generated jobs

## Key Improvements for Frontend UX

1. Friendly quality messages:
   - explains what score/status means
   - explains why score is low
   - provides actionable recommendations
2. Structured quality breakdown:
   - weighted contribution from license, purl, hash coverage
3. Reference-backed interpretation:
   - response now points to `documentation/SBOM_Quality.md`

## Runtime and Environment Notes

Observed environment issues included interpreter drift and missing dependencies. To stabilize demo/runtime:

1. Dedicated frontend API scripts were added under `scripts/`.
2. Dedicated runtime requirements were added in `requirements_frontend_api.txt`.
3. Prefer script-driven startup instead of ad hoc interpreter commands.

## Suggested Contribution Workflow (Open Source)

Because upstream is an open source repository with fork-based contribution:

1. Create issue in upstream repo first.
2. Fork upstream repository.
3. Push branch to fork.
4. Open PR from fork branch to upstream.

## Status

POC implementation is ready on local branch `capycli-poc` and prepared for fork-based PR workflow.
