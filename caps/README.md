# Client Capability Mesh — Bundled Caps

This directory ships with client-capmesh and contains the capability packages
(SKILL.md files, agents, configs) available to customer installations.

## Structure

Caps follow the standard plugin/skill directory format:

```
caps/
  <plugin-name>/
    skills/
      <skill-name>/
        SKILL.md
    agents/
      <agent-name>.md
```

## Adding Customer Caps

Place customer-specific capability packages under this directory. The mesh
will automatically discover and ingest them on startup or when
`capmesh ingest` is run.

## Default Caps

Customer installations ship with the core capmesh tooling caps:
- `capmesh-admin` — administration and configuration of the local mesh
- `capmesh-discover` — capability discovery and search for the local mesh

Additional caps are added per customer deployment.
