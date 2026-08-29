//! ASCII directory tree rendering, for at-a-glance navigation in the
//! packed artifact.

use std::collections::HashMap;

#[derive(Default)]
struct TreeNode {
    children: HashMap<String, TreeNode>,
}

/// ASCII directory tree (lexical order, directories before files at each
/// level) for `paths`.
pub fn render_tree(paths: &[String]) -> Vec<String> {
    let mut root = TreeNode::default();
    for p in paths {
        let mut node = &mut root;
        for part in p.split('/') {
            node = node.children.entry(part.to_string()).or_default();
        }
    }
    let mut lines = vec![".".to_string()];
    walk(&root, "", &mut lines);
    lines
}

fn walk(node: &TreeNode, prefix: &str, lines: &mut Vec<String>) {
    let mut items: Vec<(&String, &TreeNode)> = node.children.iter().collect();
    // Directories (non-empty children) before files (empty), then by name —
    // mirrors Python's `sorted(..., key=lambda kv: (not kv[1], kv[0]))`.
    items.sort_by(|a, b| {
        let a_is_file = a.1.children.is_empty();
        let b_is_file = b.1.children.is_empty();
        a_is_file.cmp(&b_is_file).then_with(|| a.0.cmp(b.0))
    });
    let n = items.len();
    for (i, (name, child)) in items.into_iter().enumerate() {
        let last = i == n - 1;
        let branch = if last { "`-- " } else { "|-- " };
        let is_dir = !child.children.is_empty();
        let suffix = if is_dir { "/" } else { "" };
        lines.push(format!("{prefix}{branch}{name}{suffix}"));
        if is_dir {
            let new_prefix = format!("{prefix}{}", if last { "    " } else { "|   " });
            walk(child, &new_prefix, lines);
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tree_tests.rs");
}
