use super::LanguageResolver;
use std::collections::HashMap;

pub struct JSTSResolver {
    project_root: String,
    all_files: Box<[String]>,
}

pub struct JSTSModResolver {
    // stem:{[files]}
    // e.g. "/project/src/db" : [".../db.ts", ".../db.js"]
    stem_index: HashMap<String, Vec<String>>,
}

impl JSTSResolver {
    pub fn new(base_dir: &str, all_files: &[String]) -> Self {
        let project_root = base_dir.to_string();
        Self {
            project_root,
            all_files: all_files.to_vec().into_boxed_slice(),
        }
    }
}

impl JSTSModResolver {
    fn new(all_files: &[String]) -> Self {
        let mut stem_index: HashMap<String, Vec<String>> = HashMap::new();
        for file in all_files {
            // strip extension to get the stem
            let stem = match file.rfind('.') {
                Some(i) => file[..i].to_string(),
                None => file.clone(),
            };
            stem_index.entry(stem).or_default().push(file.clone());
        }
        Self { stem_index }
    }
    fn resolve(&self,stem:&str) ->Vec<String>{
        // O(1) — just a HashMap lookup
        self.stem_index.get(stem).cloned().unwrap_or_default()
    }
}

impl LanguageResolver for JSTSResolver {
    fn accepts(&self, file_path: &str) -> bool {
        matches!(
            file_path.rsplit('.').next().unwrap_or(""),
            "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx"
        )
    }

    fn resolve(&self, stem: &str) -> Vec<String> {
        // create the new resolver first, then
        let resolver=JSTSModResolver::new(&self.all_files);
        resolver.resolve(stem)
    }
}
