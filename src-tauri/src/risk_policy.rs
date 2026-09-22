use serde::{Deserialize, Serialize};

use crate::permission_policy::ApprovalScope;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskRequestInput {
    pub command: Vec<String>,
    pub operation_class: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    pub class: RiskClass,
    pub reason: String,
    pub rule: String,
    pub allowed_scopes: Vec<ApprovalScope>,
}

impl RiskAssessment {
    pub fn allows_scope(&self, scope: ApprovalScope) -> bool {
        scope == ApprovalScope::Deny || self.allowed_scopes.contains(&scope)
    }
}

pub fn assess(input: &RiskRequestInput) -> Result<RiskAssessment, String> {
    assess_command(&input.command, &input.operation_class)
}

pub fn assess_command(command: &[String], operation_class: &str) -> Result<RiskAssessment, String> {
    if command.is_empty() || command.iter().any(|part| part.trim().is_empty()) {
        return Err("risk assessment requires a non-empty argv array".to_string());
    }

    let executable = basename_lower(&command[0]);
    let args = command[1..]
        .iter()
        .map(|arg| arg.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let operation_class = operation_class.trim().to_ascii_lowercase();

    if let Some(assessment) = classify_interpreter(&executable, &args) {
        return Ok(assessment);
    }

    if let Some(assessment) = classify_git(&executable, &args) {
        return Ok(assessment);
    }

    if let Some(assessment) = classify_package_publish(&executable, &args) {
        return Ok(assessment);
    }

    if let Some(assessment) = classify_infrastructure(&executable, &args) {
        return Ok(assessment);
    }

    if let Some(assessment) = classify_destructive_filesystem(&executable, &args) {
        return Ok(assessment);
    }

    match operation_class.as_str() {
        "read" | "read_only" | "readonly" | "inspect" | "status" => Ok(low(
            "operation-class-read",
            "The request is classified as read-only by its operation class.",
        )),
        "write" | "local_write" | "install" | "generate" | "commit" => Ok(medium(
            "operation-class-local-write",
            "The request can modify local workspace state.",
        )),
        "network_write" | "external_write" | "publish" | "deploy" | "push" => Ok(high(
            "operation-class-external-side-effect",
            "The request can change a remote or external system.",
        )),
        "critical" | "destructive" | "privileged" => Ok(critical(
            "operation-class-critical",
            "The request is explicitly marked destructive, privileged, or critical.",
        )),
        _ => Ok(medium(
            "unknown-operation-class",
            "The operation class is not recognized as read-only; ShellWarden treats it as a local-write risk by default.",
        )),
    }
}

fn classify_interpreter(executable: &str, args: &[String]) -> Option<RiskAssessment> {
    let generic_shell = matches!(
        executable,
        "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "cmd"
            | "cmd.exe"
            | "bash"
            | "bash.exe"
            | "sh"
            | "zsh"
            | "fish"
    );

    if generic_shell {
        return Some(critical(
            "general-purpose-shell",
            "General-purpose shells can execute arbitrary commands and collapse command-level restrictions.",
        ));
    }

    let interpreter_eval = match executable {
        "python" | "python.exe" | "python3" | "python3.exe" => has_any(args, &["-c", "-m"]),
        "node" | "node.exe" => has_any(args, &["-e", "--eval", "-p", "--print"]),
        "ruby" | "ruby.exe" | "perl" | "perl.exe" => has_any(args, &["-e"]),
        _ => false,
    };

    interpreter_eval.then(|| {
        critical(
            "interpreter-eval",
            "Interpreter eval/module execution can run arbitrary code and bypass narrower command policy.",
        )
    })
}

fn classify_git(executable: &str, args: &[String]) -> Option<RiskAssessment> {
    if executable != "git" && executable != "git.exe" {
        return None;
    }

    let subcommand = first_positional(args)?;

    if subcommand == "push" {
        if has_any(
            args,
            &[
                "--force",
                "-f",
                "--force-with-lease",
                "--force-if-includes",
                "--mirror",
                "--delete",
            ],
        ) {
            return Some(critical(
                "git-destructive-remote",
                "This Git push can rewrite or delete remote history/refs.",
            ));
        }

        return Some(high(
            "git-push",
            "git push changes a remote repository.",
        ));
    }

    if subcommand == "reset" && has_any(args, &["--hard"]) {
        return Some(critical(
            "git-reset-hard",
            "git reset --hard can discard local working-tree changes.",
        ));
    }

    if subcommand == "clean"
        && (has_compact_flag(args, 'f') || has_any(args, &["--force"]))
        && (has_compact_flag(args, 'd') || has_any(args, &["--directories"]))
    {
        return Some(critical(
            "git-clean-destructive",
            "Forced recursive git clean can permanently remove untracked files/directories.",
        ));
    }

    if matches!(
        subcommand.as_str(),
        "commit" | "checkout" | "switch" | "restore" | "merge" | "rebase" | "cherry-pick"
    ) {
        return Some(medium(
            "git-local-write",
            "This Git operation can modify local repository state.",
        ));
    }

    if matches!(
        subcommand.as_str(),
        "status" | "diff" | "log" | "show" | "branch" | "rev-parse" | "remote"
    ) {
        return Some(low(
            "git-read",
            "This Git operation is classified as repository inspection.",
        ));
    }

    None
}

fn classify_package_publish(executable: &str, args: &[String]) -> Option<RiskAssessment> {
    let first = first_positional(args);

    match (executable, first.as_deref()) {
        ("npm" | "npm.cmd", Some("publish"))
        | ("pnpm" | "pnpm.cmd", Some("publish"))
        | ("yarn" | "yarn.cmd", Some("npm"))
            if args.iter().any(|arg| arg == "publish") =>
        {
            Some(high(
                "package-publish",
                "Publishing a package changes an external registry.",
            ))
        }
        ("cargo" | "cargo.exe", Some("publish")) => Some(high(
            "cargo-publish",
            "cargo publish changes an external package registry.",
        )),
        ("dotnet" | "dotnet.exe", Some("nuget"))
            if args.iter().any(|arg| arg == "push") =>
        {
            Some(high(
                "nuget-push",
                "dotnet nuget push changes an external package registry.",
            ))
        }
        _ => None,
    }
}

fn classify_infrastructure(executable: &str, args: &[String]) -> Option<RiskAssessment> {
    let first = first_positional(args)?;

    match executable {
        "terraform" | "terraform.exe" | "tofu" | "tofu.exe" => {
            if first == "destroy" {
                Some(critical(
                    "infrastructure-destroy",
                    "Infrastructure destroy can remove external resources.",
                ))
            } else if first == "apply" {
                Some(high(
                    "infrastructure-apply",
                    "Infrastructure apply can create or change external resources.",
                ))
            } else {
                None
            }
        }
        "kubectl" | "kubectl.exe" => {
            if matches!(first.as_str(), "delete" | "replace") {
                Some(critical(
                    "cluster-destructive-write",
                    "This Kubernetes operation can delete or replace cluster resources.",
                ))
            } else if matches!(
                first.as_str(),
                "apply" | "create" | "patch" | "edit" | "rollout" | "scale"
            ) {
                Some(high(
                    "cluster-write",
                    "This Kubernetes operation can change cluster resources.",
                ))
            } else {
                None
            }
        }
        "gh" | "gh.exe" => {
            if (first == "pr" && args.iter().any(|arg| arg == "merge"))
                || (first == "release" && args.iter().any(|arg| arg == "create"))
            {
                Some(high(
                    "github-external-write",
                    "This GitHub CLI operation changes remote GitHub state.",
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn classify_destructive_filesystem(executable: &str, args: &[String]) -> Option<RiskAssessment> {
    match executable {
        "rm" => {
            let recursive = has_any(args, &["--recursive"]) || has_compact_flag(args, 'r');
            let force = has_any(args, &["--force"]) || has_compact_flag(args, 'f');
            (recursive && force).then(|| {
                critical(
                    "recursive-forced-delete",
                    "Recursive forced deletion can permanently remove directory trees.",
                )
            })
        }
        "rmdir" if has_any(args, &["/s", "/q"]) => Some(critical(
            "recursive-directory-delete",
            "Recursive directory deletion can permanently remove directory trees.",
        )),
        "del" | "erase" if has_any(args, &["/s", "/q", "/f"]) => Some(critical(
            "recursive-file-delete",
            "Recursive/forced file deletion can permanently remove files.",
        )),
        "format" | "format.com" | "diskpart" | "reg" | "reg.exe" => Some(critical(
            "system-destructive-tool",
            "This system utility can modify disks, registry state, or other machine-level resources.",
        )),
        "sudo" | "doas" | "runas" | "runas.exe" => Some(critical(
            "privilege-elevation",
            "Privilege elevation can expand execution authority beyond the current process context.",
        )),
        _ => None,
    }
}

fn basename_lower(raw: &str) -> String {
    raw.rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw)
        .to_ascii_lowercase()
}

fn first_positional(args: &[String]) -> Option<String> {
    args.iter().find(|arg| !arg.starts_with('-')).cloned()
}

fn has_any(args: &[String], needles: &[&str]) -> bool {
    args.iter().any(|arg| needles.contains(&arg.as_str()))
}

fn has_compact_flag(args: &[String], flag: char) -> bool {
    args.iter().any(|arg| {
        arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.chars().skip(1).any(|candidate| candidate == flag)
    })
}

fn low(rule: &str, reason: &str) -> RiskAssessment {
    assessment(
        RiskClass::Low,
        rule,
        reason,
        vec![
            ApprovalScope::Once,
            ApprovalScope::Session,
            ApprovalScope::ExactRequest,
            ApprovalScope::ExactDirectory,
            ApprovalScope::DirectoryTree,
            ApprovalScope::Always,
            ApprovalScope::Deny,
        ],
    )
}

fn medium(rule: &str, reason: &str) -> RiskAssessment {
    assessment(
        RiskClass::Medium,
        rule,
        reason,
        vec![
            ApprovalScope::Once,
            ApprovalScope::Session,
            ApprovalScope::ExactRequest,
            ApprovalScope::ExactDirectory,
            ApprovalScope::DirectoryTree,
            ApprovalScope::Deny,
        ],
    )
}

fn high(rule: &str, reason: &str) -> RiskAssessment {
    assessment(
        RiskClass::High,
        rule,
        reason,
        vec![
            ApprovalScope::Once,
            ApprovalScope::Session,
            ApprovalScope::ExactRequest,
            ApprovalScope::ExactDirectory,
            ApprovalScope::Deny,
        ],
    )
}

fn critical(rule: &str, reason: &str) -> RiskAssessment {
    assessment(
        RiskClass::Critical,
        rule,
        reason,
        vec![
            ApprovalScope::Once,
            ApprovalScope::Session,
            ApprovalScope::Deny,
        ],
    )
}

fn assessment(
    class: RiskClass,
    rule: &str,
    reason: &str,
    allowed_scopes: Vec<ApprovalScope>,
) -> RiskAssessment {
    RiskAssessment {
        class,
        reason: reason.to_string(),
        rule: rule.to_string(),
        allowed_scopes,
    }
}

#[cfg(test)]
mod tests {
    use super::{assess_command, RiskClass};
    use crate::permission_policy::ApprovalScope;

    fn assess(argv: &[&str], operation_class: &str) -> super::RiskAssessment {
        assess_command(
            &argv.iter().map(|part| part.to_string()).collect::<Vec<_>>(),
            operation_class,
        )
        .expect("risk assessment")
    }

    #[test]
    fn git_status_is_low_and_can_be_always_allowed() {
        let risk = assess(&["git", "status"], "read");
        assert_eq!(risk.class, RiskClass::Low);
        assert!(risk.allowed_scopes.contains(&ApprovalScope::Always));
    }

    #[test]
    fn ordinary_git_push_is_high_without_tree_or_always_scope() {
        let risk = assess(&["git", "push", "origin", "feature"], "external_write");
        assert_eq!(risk.class, RiskClass::High);
        assert!(risk.allowed_scopes.contains(&ApprovalScope::ExactDirectory));
        assert!(!risk.allowed_scopes.contains(&ApprovalScope::DirectoryTree));
        assert!(!risk.allowed_scopes.contains(&ApprovalScope::Always));
    }

    #[test]
    fn force_push_is_critical_and_only_temporary_allow_is_possible() {
        for flag in ["--force", "-f", "--force-with-lease"] {
            let risk = assess(&["git", "push", flag, "origin", "main"], "external_write");
            assert_eq!(risk.class, RiskClass::Critical);
            assert!(risk.allowed_scopes.contains(&ApprovalScope::Once));
            assert!(risk.allowed_scopes.contains(&ApprovalScope::Session));
            assert!(!risk.allowed_scopes.contains(&ApprovalScope::ExactRequest));
            assert!(!risk.allowed_scopes.contains(&ApprovalScope::Always));
        }
    }

    #[test]
    fn general_shells_and_eval_interpreters_are_critical() {
        for argv in [
            vec!["powershell", "-Command", "Get-ChildItem"],
            vec!["cmd", "/C", "dir"],
            vec!["bash", "-lc", "ls"],
            vec!["python", "-c", "print('x')"],
            vec!["node", "-e", "console.log('x')"],
        ] {
            let risk = assess(&argv, "read");
            assert_eq!(risk.class, RiskClass::Critical, "{argv:?}");
            assert!(!risk.allowed_scopes.contains(&ApprovalScope::Always));
        }
    }

    #[test]
    fn destructive_and_deployment_commands_are_elevated() {
        assert_eq!(
            assess(&["rm", "-rf", "build"], "write").class,
            RiskClass::Critical
        );
        assert_eq!(
            assess(&["terraform", "destroy"], "external_write").class,
            RiskClass::Critical
        );
        assert_eq!(
            assess(&["terraform", "apply"], "external_write").class,
            RiskClass::High
        );
        assert_eq!(
            assess(&["npm", "publish"], "external_write").class,
            RiskClass::High
        );
    }

    #[test]
    fn unknown_operation_class_defaults_to_medium_not_low() {
        let risk = assess(&["custom-tool", "do-thing"], "mystery");
        assert_eq!(risk.class, RiskClass::Medium);
        assert!(!risk.allowed_scopes.contains(&ApprovalScope::Always));
    }
}
