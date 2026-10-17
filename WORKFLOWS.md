# Workflows (skills)

[← README](README.md)

Workflows, shown as "skills" in the app, are reusable instructions written in Markdown.
The library is **shared per box**, so any of your bot ids works as `id`.

```rust,no_run
use grokbot_api::Client;

async fn skills(client: &Client, bot: &str) -> grokbot_api::Result<()> {
    for w in client.get_agent_workflows(bot).await? {
        println!("{} [{}] {}", w.id, w.source, w.name);
    }

    let result = client
        .import_agent_workflow_text(bot, "# Triage\n\nLabel new issues by area.")
        .await?;
    for w in &result.imported {
        println!("imported {}", w.name);
    }
    for s in &result.skipped {
        println!("skipped: {}", s.reason);
    }

    client.delete_agent_workflow(bot, "workflow-id").await?;
    Ok(())
}
```

`Workflow` fields:
- `id`: numeric ids become strings.
- `name`, `description`
- `source`: `workflow` (library, the default), `managed`, `plugin` or `automation`.
- `source_ref`
- `plugin_id`

Records without a usable id are skipped. Both `[...]` and `{workflows: [...]}` responses
are accepted.

`import_agent_workflow_text(id, markdown)` sends `{id, markdown}`.
- Locally it rejects empty Markdown and anything longer than `SKILL_MAX_BODY_LENGTH`
  (100,000 characters; Grok Bot would truncate it). Nothing is sent in either case.
- The returned `ImportResult` has:
  - `workflows`: the library after the import, if echoed
  - `imported`
  - `skipped`: each with a `reason`, `"rejected"` when none is given

`delete_agent_workflow(id, workflow_id)` sends `{id, workflowId}`.
