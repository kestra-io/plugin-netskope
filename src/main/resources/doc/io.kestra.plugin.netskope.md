# How to use the Netskope plugin

Fetch events, alerts, and audit logs from Netskope Security Cloud, and manage users and policy groups from Kestra flows.

## Authentication

Netskope tasks use one of two auth bases:

**REST API tasks** (`events.*`, `remediation.*`): set `baseUrl` (your Netskope tenant URL, e.g. `https://tenant.goskope.com`, required) and `apiToken` (your Netskope v2 API token, required).

**SCIM tasks** (`scim.*`): set `baseUrl` (required) and `scimToken` (your SCIM 2.0 Bearer token, required).

Store secrets in [secrets](https://kestra.io/docs/concepts/secret) and apply connection properties globally with [plugin defaults](https://kestra.io/docs/workflow-components/plugin-defaults).

## Tasks

`events.GetEvents` fetches events via the Netskope v2 data export endpoint — optionally set `eventType` (e.g. `application`, `network`, `page`, `infrastructure`, `audit`; defaults to `application`) and `query` (NRSQL filter). Stores the JSON response to Kestra internal storage and outputs `uri` and `eventCount`.

`events.GetAlerts` fetches alerts — optionally set `alertType` (e.g. `malware`, `dlp`, `policy`, `compromised-credentials`; defaults to `malware`) and `query` (NRSQL filter). Outputs `uri` and `alertCount`.

`events.AuditLogs` fetches the audit trail — optionally set `lookbackPeriod` (ISO 8601 duration, e.g. `PT24H`; omit to return all available logs). Outputs `uri` and `logCount`.

`remediation.UpdateAlert` updates the status of an alert — set `alertId` and `status` (both required; `status` must be `acknowledged` or `dismissed`). Optionally set `note`. Outputs `alertId` and `updatedStatus`.

`remediation.UpdatePolicyGroup` adds or removes a URL from a URL list policy group — set `policyGroupId`, `operation` (`ADD` or `REMOVE`), and `entity` (the URL or entity to add or remove, all required). Outputs `policyGroupId` and `operation`.

`scim.ManageUser` activates or deactivates a user via SCIM 2.0 — set `userId` and `active` (both required). Outputs `userId` and `active`.

`scim.PatchGroup` adds or removes a member from a SCIM group — set `groupId`, `operation` (`ADD` or `REMOVE`), and `memberEmail` (all required). Outputs `groupId` and `operation`.
