# Agents, groups and team agents

[← README](README.md)

Agents are bots or groups of bots. All methods are on `Client` and return
`grokbot_api::Result`.

## Listing

```rust,no_run
use grokbot_api::Client;

async fn sidebar(client: &Client) -> grokbot_api::Result<()> {
    for agent in client.list_agents().await? {
        if agent.hidden_from_sidebar == Some(true) {
            continue; // hidden agents are included; filter them yourself
        }
        let kind = if agent.is_group { "group" } else { "bot" };
        println!("{} {kind} {}", agent.id, agent.display_name());
    }
    Ok(())
}
```

`listAgents` may answer `{agents: [...]}`, a bare array or `{agent: {...}}`; all are
accepted, and records without an id are skipped. `Agent` fields:
- `id`
- `name`, `title`, `description`
- `avatar_shape`, `avatar_color`
- `notify_on_updates`, `hidden_from_sidebar`: `None` when absent
- `is_group`: from `isGroup`, else true when there are members
- `member_ids`

`display_name()` returns the name, else the title, else the id. `Agent::from_value` parses a
raw record.

## Creating, updating and deleting

```rust,no_run
use grokbot_api::{AgentProfile, Client, CreateAgent};

async fn example(client: &Client) -> grokbot_api::Result<()> {
    let created = client
        .create_agent(&CreateAgent {
            name: "Researcher".into(),
            description: "Finds sources".into(),
            avatar_shape: "hex".into(),
            avatar_color: "violet".into(),
            ..Default::default()
        })
        .await?; // Some(agent) when the server echoes it

    let id = created.map(|a| a.id).unwrap_or_default();
    client
        .update_agent(&id, &AgentProfile {
            name: "Researcher".into(),
            description: "Finds and checks sources".into(),
            title: Some("Research".into()),
            ..Default::default()
        })
        .await?;
    client.set_agent_notify_on_updates(&id, true).await?;
    client.set_agent_hidden_from_sidebar(&id, false).await?;
    client.delete_agent(&id).await?;
    Ok(())
}
```

These checks run locally (`Error::Validation`, nothing is sent):

- Names must not be blank. `update_agent` trims the name.
- Avatar shapes must be one of `AVATAR_SHAPES` and colors one of `AVATAR_COLORS`. An empty
  string means the server default.
- `createAgent` is always sent with `origin: "user"`.

## Groups

```rust,no_run
use grokbot_api::{Client, CreateGroup};

async fn example(client: &Client) -> grokbot_api::Result<()> {
    let group = client
        .create_group(&CreateGroup {
            name: "Review board".into(),
            description: String::new(),
            member_agent_ids: vec!["bot-a".into(), "bot-b".into()],
        })
        .await?;
    if let Some(g) = group {
        client.set_group_members(&g.id, &["bot-a".to_string()]).await?;
    }
    Ok(())
}
```

Member lists are de-duplicated and empty ids are dropped. A group must have 1 to
`MAX_GROUP_MEMBERS` (6) members. Groups cannot contain groups; the server enforces this.

## Team agents

The gateway's `listAgents` only returns **your** agents. Agents that teammates share with
you come from the Cursor backend (`GrokBotService/ListGrokBotTeamAgents`), so
`list_team_agents` only works for clients built from a Cursor token. A plain session client
returns `Ok(None)`.

```rust,no_run
use grokbot_api::Client;

async fn example(client: &Client) -> grokbot_api::Result<()> {
    if let Some(team) = client.list_team_agents().await? {
        for a in team.iter().filter(|a| !a.viewer_is_owner) {
            println!("{} shared by {:?}", a.name, a.owner_display_name);
        }
    }
    Ok(())
}
```

`TeamAgent` fields:
- `agent_id`, `name`, `description`
- `viewer_is_owner`
- `team_visible`: visibility is `GROK_BOT_AGENT_VISIBILITY_TEAM`
- `viewer_session_id`
- `owner_display_name`
- `is_room`: kind is `GROK_BOT_AGENT_KIND_ROOM`

**Viewer sessions.** To talk to an agent someone else owns, the gateway needs your viewer
session as `sessionId`. `list_team_agents` remembers it for each shared agent. After that,
`send_prompt`, `prompt_acceptance_status` and `transcript_tail` for that agent include it
automatically. You can also set it yourself with
`client.set_agent_session(agent_id, session_id)`.
