use super::LanguageResolver;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct GolangResolver {
    project_root: String,
    all_files: Box<[String]>,
    resolver: Option<GolangModuleResolver>,
}

pub struct GolangModuleResolver {
    module_prefix: String,
    dir_index: HashMap<String, Vec<String>>,
}

impl GolangResolver {
    pub fn new(project_root: &str, all_files: &[String]) -> Self {
        Self {
            project_root: project_root.to_string(),
            all_files: all_files.to_vec().into_boxed_slice(),
            resolver: GolangModuleResolver::new(project_root, all_files),
        }
    }
}

impl GolangModuleResolver {
    pub fn new(scan_path: &str, all_files: &[String]) -> Option<Self> {
        let go_mod = format!("{}/go.mod", scan_path);
        if !Path::new(&go_mod).exists() {
            eprintln!(
                "warning: no go.mod found at '{}', Go import resolution disabled for this path",
                go_mod
            );
            return None;
        }

        let module_prefix = Self::read_module_prefix(scan_path)?;

        let mut dir_index: HashMap<String, Vec<String>> = HashMap::new();
        for file in all_files {
            if let Some(dir) = Path::new(file).parent() {
                dir_index
                    .entry(dir.to_string_lossy().to_string())
                    .or_default()
                    .push(file.clone());
            }
        }

        Some(Self {
            module_prefix,
            dir_index,
        })
    }

    fn resolve(&self, project_root: &str, import_path: &str) -> Vec<String> {
        let relative = match import_path.strip_prefix(&self.module_prefix) {
            Some(rest) => rest.trim_start_matches('/'),
            None => return vec![],
        };
        if relative.is_empty() {
            return vec![];
        }
        let key = format!("{}/{}", project_root, relative);
        self.dir_index.get(&key).cloned().unwrap_or_default()
    }

    fn read_module_prefix(project_root: &str) -> Option<String> {
        let content = fs::read_to_string(format!("{}/go.mod", project_root)).ok()?;
        content
            .lines()
            .find(|l| l.starts_with("module "))
            .and_then(|l| l.split_whitespace().nth(1))
            .map(|s| s.to_string())
    }
}

impl LanguageResolver for GolangResolver {
    fn accepts(&self, file_path: &str) -> bool {
        file_path.ends_with(".go")
    }

    fn resolve(&self, import_path: &str) -> Vec<String> {
        match self.resolver.as_ref() {
            Some(resolver) => resolver.resolve(&self.project_root, import_path),
            None => {
                // resolver is None only when go.mod was absent at construction time;
                // that was already reported in GolangModuleResolver::new(), so
                // stay silent here to avoid flooding logs on every import call.
                vec![]
            }
        }
    }
}