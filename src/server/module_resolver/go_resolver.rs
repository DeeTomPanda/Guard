use super::LanguageResolver;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct GolangResolver {
    project_root: String,
    all_files: Box<[String]>,
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
        }
    }
}

impl GolangModuleResolver {
    pub fn new(scan_path: &str, all_files: &[String]) -> Option<Self> {
        // TODO: throw error if go.mod is absent
        let go_mod = format!("{}/go.mod", scan_path);
        if !Path::new(&go_mod).exists() {
            print!("errrr");
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

    fn resolve(&self, project_root: &str,import_path: &str) -> Vec<String> {
        let relative = match import_path.strip_prefix(&self.module_prefix) {
            Some(rest) => rest.trim_start_matches('/'),
            None => return vec![],
        };
        if relative.is_empty() {
            return vec![];
        }
        let key = format!("{}/{}", project_root, relative);
        dbg!(project_root,import_path,relative);
        self.dir_index.get(&key).cloned().unwrap_or_default()
    }

    // finds the module line and takes the path
    // eg like["module", "myapp"] becomes "myapp"
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
        // create the new module resolver
        let mod_resolver=GolangModuleResolver::new(&self.project_root,&self.all_files);
        if let Some(resolver)=mod_resolver{
            resolver.resolve(&self.project_root, import_path)
        }else{
            // TODO: Report error!
            vec![]
        }
    }
}
