use std::{fs, path::Path, process::Command};

#[test]
fn tracked_repository_is_free_of_retired_identifier() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live below the repository root");
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repository)
        .output()
        .expect("git must be available in CI");
    assert!(output.status.success(), "git ls-files failed");

    let forbidden = String::from_utf8(vec![99, 115, 109, 112])
        .expect("the retired identifier bytes are valid UTF-8");
    let mut matches = Vec::new();

    for raw_path in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = String::from_utf8_lossy(raw_path);
        let path = repository.join(relative.as_ref());
        if relative.to_ascii_lowercase().contains(&forbidden) {
            matches.push(format!("path: {relative}"));
        }

        let contents =
            fs::read(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        if String::from_utf8_lossy(&contents)
            .to_ascii_lowercase()
            .contains(&forbidden)
        {
            matches.push(format!("content: {relative}"));
        }
    }

    assert!(
        matches.is_empty(),
        "retired identifier found in tracked repository:\n{}",
        matches.join("\n")
    );
}
