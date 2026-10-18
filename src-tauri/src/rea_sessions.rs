//! REA processes launched by MCP clients. A client owns its REA process over
//! stdio, so the app cannot close the analysis sessions inside it. It can end
//! a whole process tree (REA's job objects also end Ghidra and the other
//! providers it started), end trees whose client has exited, and remove the
//! `rea-*` temporary folders REA leaves behind after an abrupt exit.
use crate::{i18n::tr, models::*};
use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, SystemTime},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Clone, Debug)]
struct Proc {
    pid: u32,
    parent: Option<u32>,
    name: String,
    cmd: String,
    memory: u64,
    /// Seconds since the Unix epoch.
    start: u64,
}

/// A REA MCP server, recognized by its package and `mcp` subcommand so that
/// `rea doctor` and unrelated Node processes are never matched.
fn is_rea(p: &Proc) -> bool {
    let cmd = p.cmd.to_ascii_lowercase();
    cmd.contains("rea-agents")
        && cmd
            .split_whitespace()
            .any(|arg| arg.trim_matches('"') == "mcp")
}
fn stem(p: &Proc) -> String {
    let name = p.name.to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).to_owned()
}
/// Shells and launchers between a client and REA.
fn is_launcher(p: &Proc) -> bool {
    matches!(
        stem(p).as_str(),
        "cmd" | "conhost" | "sh" | "bash" | "zsh" | "dash" | "fish" | "powershell" | "pwsh"
    )
}
fn client_label(p: &Proc) -> String {
    let cmd = p.cmd.to_ascii_lowercase();
    match stem(p).as_str() {
        "codex" => "Codex",
        "claude" => "Claude Code",
        "cursor" => "Cursor",
        "devin" | "devin-desktop" => "Devin",
        "codegraph-desktop" => "CodeGraph Desktop",
        _ if cmd.contains("@anthropic-ai/claude-code") || cmd.contains("claude-code") => {
            "Claude Code"
        }
        _ if cmd.contains("\\devin\\") || cmd.contains("/devin/") => "Devin",
        _ if cmd.contains("cursor") => "Cursor",
        _ => return p.name.clone(),
    }
    .into()
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pid: u32,
    /// The client that launched it; `None` once that client has exited.
    client: Option<String>,
    client_pid: Option<u32>,
    /// Seconds since the Unix epoch.
    started_at: u64,
    /// Resident memory of the whole tree, including analysis providers.
    memory: u64,
    processes: usize,
    orphan: bool,
}

struct Tree {
    session: Session,
    /// Every process in the tree, descendants before ancestors.
    pids: Vec<u32>,
}

fn trees(procs: &[Proc]) -> Vec<Tree> {
    let by_pid: HashMap<u32, &Proc> = procs.iter().map(|p| (p.pid, p)).collect();
    // A recorded parent counts only if it started first; Windows reuses ids.
    let parent = |p: &Proc| {
        p.parent
            .and_then(|id| by_pid.get(&id).copied())
            .filter(|parent| parent.start <= p.start && parent.pid != p.pid)
    };
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in procs {
        if let Some(parent) = parent(p) {
            children.entry(parent.pid).or_default().push(p.pid);
        }
    }
    let mut trees = vec![];
    // npx relaunches REA through a shell (`cmd /c rea mcp`), so a REA process
    // is a root only when no ancestor is one.
    let nested = |p: &Proc| {
        let mut ancestor = parent(p);
        // Bounded in case recorded parents form a cycle.
        for _ in 0..64 {
            let Some(a) = ancestor else { break };
            if is_rea(a) {
                return true;
            }
            ancestor = parent(a);
        }
        false
    };
    for root in procs.iter().filter(|p| is_rea(p) && !nested(p)) {
        let mut pids = vec![];
        let mut queue = vec![root.pid];
        while let Some(pid) = queue.pop() {
            if pids.contains(&pid) {
                continue;
            }
            pids.push(pid);
            queue.extend(children.get(&pid).into_iter().flatten());
        }
        let mut client = parent(root);
        while let Some(p) = client.filter(|p| is_launcher(p) || is_rea(p)) {
            client = parent(p);
        }
        pids.reverse();
        trees.push(Tree {
            session: Session {
                pid: root.pid,
                client: client.map(client_label),
                client_pid: client.map(|p| p.pid),
                started_at: root.start,
                memory: pids.iter().map(|pid| by_pid[pid].memory).sum(),
                processes: pids.len(),
                orphan: client.is_none(),
            },
            pids,
        });
    }
    trees.sort_by_key(|tree| tree.session.started_at);
    trees
}

fn snapshot() -> (System, Vec<Proc>) {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        // Linux would otherwise list every thread as a process of its own.
        ProcessRefreshKind::nothing()
            .without_tasks()
            .with_cmd(UpdateKind::Always)
            .with_memory(),
    );
    let procs = system
        .processes()
        .values()
        .map(|p| Proc {
            pid: p.pid().as_u32(),
            parent: p.parent().map(Pid::as_u32),
            name: p.name().to_string_lossy().into_owned(),
            cmd: p
                .cmd()
                .iter()
                .map(|arg| arg.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            memory: p.memory(),
            start: p.start_time(),
        })
        .collect();
    (system, procs)
}
/// Ends every process in the tree, descendants first; tries all of them even
/// after one fails.
fn end(system: &System, tree: &Tree) -> bool {
    tree.pids
        .iter()
        .filter(|pid| {
            !system
                .process(Pid::from_u32(**pid))
                .is_none_or(|p| p.kill())
        })
        .count()
        == 0
}

fn temp_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    // REA puts Hopper sessions under /tmp on macOS.
    if cfg!(target_os = "macos")
        && !roots
            .iter()
            .any(|root| root == std::path::Path::new("/tmp"))
    {
        roots.push("/tmp".into());
    }
    roots
}
/// `rea-*` temporary folders created before `cutoff`, the start of the oldest
/// running REA process; younger folders may belong to it. REA only creates
/// folders there, so files with the prefix are left alone.
fn leftovers(cutoff: Option<u64>) -> Vec<PathBuf> {
    let cutoff = cutoff.map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
    temp_roots()
        .into_iter()
        .filter_map(|root| std::fs::read_dir(root).ok())
        .flatten()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("rea-"))
        .filter(|entry| {
            let Ok(meta) = entry.metadata() else {
                return false;
            };
            meta.is_dir() && stale(meta.created().or_else(|_| meta.modified()).ok(), cutoff)
        })
        .map(|entry| entry.path())
        .collect()
}
fn stale(created: Option<SystemTime>, cutoff: Option<SystemTime>) -> bool {
    match (created, cutoff) {
        (_, None) => true,
        (Some(created), Some(cutoff)) => created < cutoff,
        (None, Some(_)) => false,
    }
}
fn oldest_live(trees: &[Tree]) -> Option<u64> {
    trees
        .iter()
        .filter(|tree| !tree.session.orphan)
        .map(|tree| tree.session.started_at)
        .min()
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sessions {
    sessions: Vec<Session>,
    /// Temporary `rea-*` folders that cleanup would remove.
    leftovers: usize,
}
fn list() -> Sessions {
    let (_, procs) = snapshot();
    let trees = trees(&procs);
    let cutoff = oldest_live(&trees);
    Sessions {
        leftovers: leftovers(cutoff).len(),
        sessions: trees.into_iter().map(|tree| tree.session).collect(),
    }
}
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| AppError::new("TASK_FAILED", e.to_string()))
}

#[tauri::command]
pub async fn list_rea_sessions() -> Result<Sessions> {
    blocking(list).await
}

/// Ends one REA process tree, checking the start time so that a reused
/// process id is never ended.
#[tauri::command]
pub async fn end_rea_session(pid: u32, started_at: u64) -> Result<Sessions> {
    blocking(move || {
        let (system, procs) = snapshot();
        let tree = trees(&procs)
            .into_iter()
            .find(|tree| tree.session.pid == pid && tree.session.started_at == started_at)
            .ok_or_else(|| {
                AppError::new(
                    "SESSION_NOT_FOUND",
                    tr("该 REA 进程已退出", "This REA process has already exited"),
                )
            })?;
        if !end(&system, &tree) {
            return Err(AppError::new(
                "SESSION_END_FAILED",
                tr(
                    "无法结束该 REA 进程，可能需要更高权限",
                    "Could not end this REA process; it may need higher privileges",
                ),
            ));
        }
        Ok(list())
    })
    .await?
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cleaned {
    ended: usize,
    removed: usize,
    /// Entries that could not be removed, with the reason.
    failed: Vec<String>,
}
/// Ends REA trees whose client has exited and removes stale temporary folders.
#[tauri::command]
pub async fn clean_rea_sessions() -> Result<Cleaned> {
    blocking(|| {
        let (system, procs) = snapshot();
        let trees = trees(&procs);
        let mut failed = vec![];
        let mut ended = 0;
        for tree in trees.iter().filter(|tree| tree.session.orphan) {
            if end(&system, tree) {
                ended += 1;
            } else {
                failed.push(format!("PID {}", tree.session.pid));
            }
        }
        if ended > 0 {
            // Let Windows release the files the ended processes held.
            std::thread::sleep(Duration::from_millis(500));
        }
        let mut removed = 0;
        for path in leftovers(oldest_live(&trees)) {
            match std::fs::remove_dir_all(&path) {
                Ok(()) => removed += 1,
                Err(error) => failed.push(format!("{}: {error}", path.display())),
            }
        }
        Cleaned {
            ended,
            removed,
            failed,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proc(pid: u32, parent: Option<u32>, name: &str, cmd: &str, start: u64) -> Proc {
        Proc {
            pid,
            parent,
            name: name.into(),
            cmd: cmd.into(),
            memory: 10,
            start,
        }
    }

    #[test]
    fn rea_trees_are_attributed_to_their_client() {
        let procs = [
            proc(1, None, "codex.exe", "codex", 100),
            proc(
                2,
                Some(1),
                "cmd.exe",
                "cmd.exe /d /c npx -y rea-agents@6.5.0 mcp",
                110,
            ),
            proc(
                3,
                Some(2),
                "node.exe",
                "node npx-cli.js -y rea-agents@6.5.0 mcp",
                111,
            ),
            // npx relaunches REA through a shell, as observed on Windows.
            proc(12, Some(3), "cmd.exe", "cmd.exe /d /s /c rea mcp", 111),
            proc(
                4,
                Some(12),
                "node.exe",
                "node C:\\npx\\rea-agents\\scripts\\rea.mjs mcp",
                112,
            ),
            proc(5, Some(4), "java.exe", "java -cp ghidra.jar", 120),
            // The client died: its id now belongs to a younger process.
            proc(6, Some(7), "node.exe", "npx -y rea-agents@6.5.0 mcp", 130),
            proc(7, None, "notepad.exe", "notepad", 140),
            // Diagnostics and unrelated Node processes are not sessions.
            proc(
                8,
                Some(1),
                "node.exe",
                "npx -y rea-agents@6.5.0 doctor",
                150,
            ),
            proc(9, Some(1), "node.exe", "node server.js mcp", 150),
            proc(10, Some(11), "node.exe", "npx -y rea-agents@6.5.0 mcp", 160),
            proc(11, None, "Cursor.exe", "Cursor.exe --type=utility", 90),
        ];
        let trees = trees(&procs);
        assert_eq!(trees.len(), 3);
        let codex = &trees[0];
        assert_eq!(codex.session.pid, 2);
        assert_eq!(codex.session.client.as_deref(), Some("Codex"));
        assert_eq!(codex.session.client_pid, Some(1));
        assert_eq!(codex.session.processes, 5);
        assert_eq!(codex.session.memory, 50);
        assert!(!codex.session.orphan);
        // Descendants end before their ancestors.
        assert_eq!(codex.pids.first(), Some(&5));
        assert_eq!(codex.pids.last(), Some(&2));
        let orphan = &trees[1];
        assert_eq!(orphan.session.pid, 6);
        assert!(orphan.session.orphan);
        assert_eq!(orphan.session.client, None);
        assert_eq!(trees[2].session.client.as_deref(), Some("Cursor"));
        assert_eq!(oldest_live(&trees), Some(110));
    }

    #[test]
    fn only_entries_older_than_live_sessions_are_stale() {
        let at = |secs| Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
        assert!(stale(at(10), None));
        assert!(stale(None, None));
        assert!(stale(at(10), at(20)));
        assert!(!stale(at(30), at(20)));
        assert!(!stale(None, at(20)));
    }

    /// Ends a stand-in REA tree: a Node process named like the REA server
    /// with a child of its own, as Ghidra would be.
    #[tokio::test]
    async fn ending_a_session_ends_its_whole_tree() {
        let Ok(node) = which::which("node") else {
            eprintln!("node is not installed; skipping");
            return;
        };
        let script = "require('child_process').spawn(process.execPath, \
                      ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' }); \
                      setInterval(() => {}, 1000)";
        let mut root = std::process::Command::new(node)
            .args(["-e", script, "rea-agents-test", "mcp"])
            .spawn()
            .unwrap();
        let pid = root.id();
        let mut found = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            found = list_rea_sessions()
                .await
                .unwrap()
                .sessions
                .into_iter()
                .find(|s| s.pid == pid && s.processes == 2);
            if found.is_some() {
                break;
            }
        }
        let session = found.expect("the stand-in REA tree is listed");
        assert!(!session.orphan);
        let error = end_rea_session(pid, session.started_at + 1).await.err();
        assert_eq!(error.unwrap().code, "SESSION_NOT_FOUND");
        let remaining = end_rea_session(pid, session.started_at).await.unwrap();
        assert!(remaining.sessions.iter().all(|s| s.pid != pid));
        root.wait().unwrap();
        let (_, procs) = snapshot();
        assert!(!procs
            .iter()
            .any(|p| p.parent == Some(pid) && p.cmd.contains("setInterval")));
    }

    /// Lists this machine's REA processes without ending anything.
    #[test]
    #[ignore = "reads the processes running on this machine"]
    fn lists_running_rea_processes() {
        println!("{}", serde_json::to_string_pretty(&list()).unwrap());
    }
}
