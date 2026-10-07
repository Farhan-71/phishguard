# Task Breakdown & Future Roadmap

This document outlines the sequential, bite-sized tasks required to move PhishGuard from a functional MVP to a production-ready, publicly distributed application.

## Stage 1: Cloud Deployment & Hardening
- [x] **Task 1.1:** Configure a production `Dockerfile` for the FastAPI backend.
- [ ] **Task 1.2:** Deploy the FastAPI backend to a scalable cloud provider (e.g., Render, AWS AppRunner, or GCP Cloud Run).
- [ ] **Task 1.3:** Set up a production PostgreSQL database (replace local SQLite) and apply SQLAlchemy migrations.
- [ ] **Task 1.4:** Update `extension/shared/api.js` `DEFAULTS` to point to the new production HTTPS endpoint.

## Stage 2: Chrome Web Store Preparation
- [ ] **Task 2.1:** Generate a 440x280 Promo Banner and high-resolution UI screenshots for the Web Store listing.
- [ ] **Task 2.2:** Write a formal Privacy Policy page hosted externally, verifying that no PII or query secrets leave the browser.
- [ ] **Task 2.3:** Package the extension (`zip`) and submit for Web Store Review.
- [ ] **Task 2.4:** Submit to Mozilla Add-ons (Firefox) for cross-browser support.

## Stage 3: Telemetry & Continuous Iteration
- [ ] **Task 3.1:** Integrate Sentry into the FastAPI backend for Python exception tracking.
- [ ] **Task 3.2:** Integrate Sentry (Browser JS SDK) into the Chrome Extension. Ensure the configuration scrubs all URLs of PII before sending error reports.
- [ ] **Task 3.3:** Implement a feedback loop: build a scheduled job to ingest user-reported false positives/negatives (from the `/report` endpoint) for periodic ML retraining.

## Stage 4: Advanced Features
- [ ] **Task 4.1:** Implement global allowlist syncing (allowing users to sync their trusted sites across multiple devices via Chrome Sync storage).
- [ ] **Task 4.2:** Expand the ML dataset with real-world PhishTank/OpenPhish feeds to replace the synthetic bootstrap data.
