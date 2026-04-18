# Kestra Template Plugin

## What

- Provides plugin components under `io.kestra.plugin.netskope`.
- Includes classes such as `AuditLogs`, `GetEvents`, `GetAlerts`, `UpdatePolicyGroup`.

## Why

- This plugin integrates Kestra with Netskope Events.
- It provides tasks to fetch alerts, events, and audit logs from Netskope Security Cloud via the REST API v2 Data Export endpoint.

## How

### Architecture

Single-module plugin. Source packages under `io.kestra.plugin`:

- `templates`

Infrastructure dependencies (Docker Compose services):

- `app`

### Key Plugin Classes

- `io.kestra.plugin.templates.Example`

### Project Structure

```
plugin-template/
├── src/main/java/io/kestra/plugin/templates/
├── src/test/java/io/kestra/plugin/templates/
├── build.gradle
└── README.md
```

## Local rules

- Base the wording on the implemented packages and classes, not on template README text.

## References

- https://kestra.io/docs/plugin-developer-guide
- https://kestra.io/docs/plugin-developer-guide/contribution-guidelines
