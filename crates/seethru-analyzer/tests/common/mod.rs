use std::fs;
use std::path::PathBuf;

pub struct TempProject {
    pub root: PathBuf,
}

impl TempProject {
    pub fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("seethru-temp-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let created = fs::create_dir_all(&root);
        assert!(created.is_ok(), "{created:?}");
        Self { root }
    }

    pub fn write(&self, rel_path: &str, content: &str) {
        let path = self.root.join(rel_path);
        if let Some(parent) = path.parent() {
            let created = fs::create_dir_all(parent);
            assert!(created.is_ok(), "{created:?}");
        }
        let written = fs::write(path, content);
        assert!(written.is_ok(), "{written:?}");
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
