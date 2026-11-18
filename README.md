# Salesforce Security Operations Center (SOC)

A Salesforce-native security dashboard built with **Apex** and **Lightning Web Components (LWC)** for identity and access monitoring.

## Capabilities

- Security posture overview and risk KPIs
- Dormant accounts (90+ days) and privileged-user visibility
- Privileged permissions, export access, and password-policy monitoring
- Failed login and weak TLS visibility
- Setup audit trail monitoring with date filters
- Account freeze/unfreeze actions through `UserLogin`
- CSV exports restricted in the UI to configured admin profiles
- Search, sorting, filtering, and light/dark themes

## Structure

```text
force-app/main/default/classes/          Apex controllers and tests
force-app/main/default/lwc/socDashboard/  LWC frontend
manifest/package.xml                      Deployment manifest
sfdx-project.json                         Salesforce DX project
```

## Requirements

- Salesforce org with access to the relevant standard security objects and setup data
- Salesforce CLI (`sf`)
- Appropriate Salesforce permissions for the deploying and dashboard users

## Deploy

```bash
sf org login web --alias soc-target
sf project deploy start --manifest manifest/package.xml --target-org soc-target
sf apex run test --tests SocDashboardControllerTest --target-org soc-target --result-format human --wait 30
```

After deployment, add `socDashboard` to a Lightning App Page, Home Page, or Lightning Tab in Lightning App Builder and assign appropriate access.

## Security considerations

**Do not publish production data, org exports, credentials, or company-specific deployment settings.**

This repository is a source-code snapshot, not a security-audited production release. The Apex controllers use `without sharing`; review object/field authorization and least-privilege access before deploying. The CSV restriction is enforced in the UI, but the underlying rows are already sent to the browser; do not treat it as a data-exfiltration boundary. Freeze/unfreeze functions change login access and require careful authorization review. Profile names used for CSV access are configurable in `SocFreezeController`.

No live Salesforce org deployment or test run was performed as part of repository packaging.

## License

No license is granted unless the repository owner adds one. Confirm ownership and employer permission before making the source public.
