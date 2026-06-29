use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

const MARKER_START: &str = "# >>> secretenv";
const MARKER_END: &str = "# <<< secretenv";

/// Standard plaintext-env patterns for import.
pub const IMPORT_GITIGNORE_LINES: &[&str] = &[".env", ".env.*", "!*.env.enc", "*.key"];

pub fn git_root(from: &Path) -> Option<PathBuf> {
    let mut dir = if from.is_file() {
        from.parent()?.to_path_buf()
    } else {
        from.to_path_buf()
    };
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

pub fn path_relative_to_repo(path: &Path, repo_root: &Path) -> String {
    path.strip_prefix(repo_root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string_lossy().into_owned())
        })
}

pub fn is_tracked(path: &Path, repo_root: &Path) -> Result<bool> {
    let rel = path_relative_to_repo(path, repo_root);
    let status = Command::new("git")
        .args(["ls-files", "--error-unmatch", &rel])
        .current_dir(repo_root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("run git ls-files for {rel}"))?;
    Ok(status.success())
}

fn line_present(content: &str, line: &str) -> bool {
    content.lines().any(|l| l.trim() == line)
}

/// Append missing lines to `.gitignore` inside a marked secretenv block.
pub fn ensure_gitignore_lines(repo_root: &Path, lines: &[&str]) -> Result<Vec<String>> {
    let gitignore_path = repo_root.join(".gitignore");
    let mut content = if gitignore_path.exists() {
        fs::read_to_string(&gitignore_path)
            .with_context(|| format!("read {}", gitignore_path.display()))?
    } else {
        String::new()
    };

    let missing: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| !line_present(&content, line))
        .collect();
    if missing.is_empty() {
        return Ok(vec![]);
    }

    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }

    if let Some(pos) = content.rfind(MARKER_END) {
        let insert = missing
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        content.insert_str(pos, &insert);
    } else {
        content.push_str(MARKER_START);
        content.push('\n');
        for line in &missing {
            content.push_str(line);
            content.push('\n');
        }
        content.push_str(MARKER_END);
        content.push('\n');
    }

    fs::write(&gitignore_path, &content)
        .with_context(|| format!("write {}", gitignore_path.display()))?;
    Ok(missing.iter().map(|s| s.to_string()).collect())
}

pub fn apply_import_gitignore(source: &Path) -> Result<Vec<String>> {
    let Some(repo_root) = git_root(source) else {
        eprintln!("not in a git repository; skipping --gitignore");
        return Ok(vec![]);
    };
    let source_rel = path_relative_to_repo(source, &repo_root);
    let mut lines: Vec<String> = IMPORT_GITIGNORE_LINES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if source_rel != ".env" && !lines.iter().any(|l| l == &source_rel) {
        lines.push(source_rel);
    }
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let added = ensure_gitignore_lines(&repo_root, &refs)?;
    if !added.is_empty() {
        eprintln!("updated .gitignore ({})", added.join(", "));
    }
    Ok(added)
}

pub fn apply_keyfile_gitignore(keyfile: &Path) -> Result<Vec<String>> {
    let Some(repo_root) = git_root(keyfile) else {
        eprintln!("not in a git repository; skipping --gitignore");
        return Ok(vec![]);
    };
    let key_rel = path_relative_to_repo(keyfile, &repo_root);
    let lines = ["*.key", key_rel.as_str()];
    let added = ensure_gitignore_lines(&repo_root, &lines)?;
    if !added.is_empty() {
        eprintln!("updated .gitignore ({})", added.join(", "));
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_gitignore_lines_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let added = ensure_gitignore_lines(root, &[".env", "*.key"]).unwrap();
        assert_eq!(added, vec![".env", "*.key"]);
        let content = fs::read_to_string(root.join(".gitignore")).unwrap();
        assert!(content.contains(MARKER_START));
        assert!(content.contains(".env"));
        let again = ensure_gitignore_lines(root, &[".env", "*.key"]).unwrap();
        assert!(again.is_empty());
    }
}
