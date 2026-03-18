use clap::Parser;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use walkdir::WalkDir;

/// Validates that a repository URL is safe to use with git clone.
/// Only allows https:// and git@ URLs, rejecting dangerous git URL schemes.
fn validate_repo_url(url: &str) -> Result<(), String> {
    // Reject dangerous git URL schemes that could execute arbitrary code
    let dangerous_prefixes = ["ext::", "fd::", "remote-ext::", "remote-fd::"];
    for prefix in &dangerous_prefixes {
        if url.to_lowercase().contains(prefix) {
            return Err(format!("Dangerous git URL scheme detected: {}", prefix));
        }
    }
    
    // Only allow https:// or git@ URLs
    if !url.starts_with("https://") && !url.starts_with("git@") {
        return Err("Only https:// and git@ URLs are allowed".to_string());
    }
    
    Ok(())
}

/// Sanitizes a repository name to prevent path traversal attacks.
/// Removes dangerous path components like "..", ".", and absolute paths.
fn sanitize_repo_name(name: &str) -> Result<String, String> {
    let sanitized = name.trim_end_matches(".git");
    
    // Reject dangerous path components
    if sanitized.contains("..") || sanitized.contains("/") || sanitized.contains("\\") {
        return Err("Repository name contains invalid path components".to_string());
    }
    
    // Reject empty names
    if sanitized.is_empty() {
        return Err("Repository name cannot be empty".to_string());
    }
    
    Ok(sanitized.to_string())
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// GitHub repository URL to clone and analyze (https:// or git@ only)
    #[arg(short, long)]
    repo: String,
}

fn main() {
    let args = Args::parse();

    // Validate repository URL for security
    if let Err(e) = validate_repo_url(&args.repo) {
        eprintln!("Invalid repository URL: {}", e);
        std::process::exit(1);
    }

    // Clone the repository
    println!("Cloning repository: {}", args.repo);
    let temp_dir = std::env::temp_dir();
    
    // Extract and sanitize repository name
    let repo_name_raw = args
        .repo
        .split('/')
        .next_back()
        .unwrap_or("repo");
    
    let repo_name = match sanitize_repo_name(repo_name_raw) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("Invalid repository name: {}", e);
            std::process::exit(1);
        }
    };
    
    let target_dir = temp_dir.join(&repo_name);

    // Remove the directory if it exists
    if target_dir.exists() {
        if let Err(e) = fs::remove_dir_all(&target_dir) {
            eprintln!("Warning: Failed to remove existing directory: {}", e);
            eprintln!("Attempting to continue anyway...");
        }
    }

    let status = Command::new("git")
        .arg("clone")
        .arg(&args.repo)
        .arg(&target_dir)
        .status()
        .expect("Failed to execute git clone");

    if !status.success() {
        eprintln!("Failed to clone repository");
        std::process::exit(1);
    }

    // Analyze the repository
    println!("Analyzing repository...");
    let analysis = analyze_repository(&target_dir);

    // Generate HTML report
    println!("Generating HTML report...");
    let html = generate_html_report(&analysis);

    // Write the report to a file
    let report_path = PathBuf::from("report.html");
    fs::write(&report_path, html).expect("Failed to write report to report.html");
    println!("Report written to: {}", report_path.display());

    // Clean up: remove the cloned repository
    if let Err(e) = fs::remove_dir_all(&target_dir) {
        eprintln!("Warning: Failed to clean up temporary directory: {}", e);
    }
}

/// Analyzes a repository directory and counts files by type and language.
fn analyze_repository(dir: &Path) -> AnalysisResult {
    let mut result = AnalysisResult::default();

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e: walkdir::Result<walkdir::DirEntry>| e.ok())
        .filter(|e: &walkdir::DirEntry| e.file_type().is_file())
    {
        // Skip files that are inside .git directories
        let path = entry.path();
        if path
            .ancestors()
            .any(|ancestor| ancestor.file_name().and_then(|s| s.to_str()) == Some(".git"))
        {
            continue;
        }

        result.total_files += 1;
        let (category, language) = get_category_and_language(entry.path());

        match category.as_str() {
            "code" => {
                *result.language_counts.entry(language).or_insert(0) += 1;
            }
            "static" => {
                result.static_count += 1;
            }
            "config" => {
                result.config_count += 1;
            }
            "other" => {
                result.other_count += 1;
            }
            _ => {}
        }
    }

    result
}

/// Determines the category and language of a file based on its extension.
/// Returns a tuple of (category, language) where category is one of:
/// "code", "static", "config", or "other".
fn get_category_and_language(path: &Path) -> (String, String) {
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Special files without extension
    if extension.is_empty() {
        match file_name {
            "Makefile" | "makefile" | "GNUmakefile" | "Kbuild" | "kernel" => {
                return ("code".to_string(), "Makefile".to_string());
            }
            "Dockerfile" => {
                return ("code".to_string(), "Dockerfile".to_string());
            }
            "Jenkinsfile" => {
                return ("code".to_string(), "Jenkinsfile".to_string());
            }
            _ => {}
        }
    }

    // Define our extension sets
    let code_exts = [
        "rs", "py", "js", "ts", "jsx", "tsx", "java", "c", "cpp", "cc", "cxx", "h", "hpp", "hxx",
        "cs", "go", "rb", "php", "swift", "kt", "scala", "m", "mm", "pl", "sh", "bash", "zsh",
        "fish", "sql",
    ];
    let static_exts = [
        "html", "htm", "css", "scss", "less", "jpg", "jpeg", "png", "gif", "svg", "ico", "woff",
        "woff2", "ttf", "eot", "otf", "mp4", "mp3", "wav", "webp",
    ];
    let config_exts = [
        "json", "yaml", "yml", "toml", "ini", "xml", "config", "conf", "lock",
    ];

    if code_exts.contains(&extension.as_str()) {
        let language = match extension.as_str() {
            "rs" => "Rust",
            "py" => "Python",
            "js" | "jsx" => "JavaScript",
            "ts" | "tsx" => "TypeScript",
            "java" => "Java",
            "c" => "C",
            "cpp" | "cc" | "cxx" => "C++",
            "h" => "C/C++ Header",
            "hpp" | "hxx" => "C++ Header",
            "cs" => "C#",
            "go" => "Go",
            "rb" => "Ruby",
            "php" => "PHP",
            "swift" => "Swift",
            "kt" => "Kotlin",
            "scala" => "Scala",
            "m" | "mm" => "Objective-C",
            "pl" => "Perl",
            "sh" | "bash" | "zsh" | "fish" => "Shell",
            "sql" => "SQL",
            _ => &extension.to_uppercase(),
        };
        return ("code".to_string(), language.to_string());
    }

    if static_exts.contains(&extension.as_str()) {
        return ("static".to_string(), String::new());
    }

    if config_exts.contains(&extension.as_str()) {
        return ("config".to_string(), String::new());
    }

    ("other".to_string(), String::new())
}

#[derive(Default)]
struct AnalysisResult {
    total_files: usize,
    language_counts: HashMap<String, usize>,
    static_count: usize,
    config_count: usize,
    other_count: usize,
}

/// Generates an HTML report with interactive charts showing the repository analysis.
/// Returns the complete HTML document as a string.
fn generate_html_report(analysis: &AnalysisResult) -> String {
    // Prepare data for pie chart: code, static, config, other
    let code_total: usize = analysis.language_counts.values().sum();
    let pie_labels = vec![
        "Code".to_string(),
        "Static".to_string(),
        "Config".to_string(),
        "Other".to_string(),
    ];
    let pie_data = vec![
        code_total,
        analysis.static_count,
        analysis.config_count,
        analysis.other_count,
    ];

    // Prepare data for bar chart: language and count
    let mut bar_labels: Vec<String> = analysis.language_counts.keys().cloned().collect();
    let mut bar_data: Vec<usize> = analysis.language_counts.values().cloned().collect();
    
    // Sort by count descending for better visualization
    let mut zipped: Vec<(String, usize)> = bar_labels
        .iter()
        .zip(bar_data.iter())
        .map(|(label, count)| (label.clone(), *count))
        .collect();
    zipped.sort_by(|a, b| b.1.cmp(&a.1));
    bar_labels = zipped.iter().map(|(label, _)| label.clone()).collect();
    bar_data = zipped.iter().map(|(_, count)| *count).collect();

    // Generate colors for charts
    let pie_colors = vec!["#36a2eb", "#ff6384", "#ffcd56", "#4bc0c0"];
    let bar_color = "rgba(54, 162, 235, 0.5)";
    let bar_border_color = "rgba(54, 162, 235, 1)";

    // Serialize data to JSON for embedding in HTML
    let pie_labels_json = serde_json::to_string(&pie_labels)
        .expect("Failed to serialize pie chart labels");
    let pie_data_json = serde_json::to_string(&pie_data)
        .expect("Failed to serialize pie chart data");
    let pie_colors_json = serde_json::to_string(&pie_colors)
        .expect("Failed to serialize pie chart colors");

    let bar_labels_json = serde_json::to_string(&bar_labels)
        .expect("Failed to serialize bar chart labels");
    let bar_data_json = serde_json::to_string(&bar_data)
        .expect("Failed to serialize bar chart data");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Repository Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .chart-container {{ width: 600px; height: 400px; margin: 20px auto; }}
        .stats {{ margin: 20px 0; }}
        .stats div {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>Repository Analysis Report</h1>
    <div class="stats">
        <div>Total Files: {total}</div>
    </div>

    <h2>File Type Distribution</h2>
    <div class="chart-container">
        <canvas id="pieChart"></canvas>
    </div>

    <h2>Language Distribution (Code Files)</h2>
    <div class="chart-container">
        <canvas id="barChart"></canvas>
    </div>

    <script>
        // Pie chart data
        const pieData = {{
            labels: {pie_labels},
            datasets: [{{
                data: {pie_data},
                backgroundColor: {pie_colors}
            }}]
        }};

        // Bar chart data
        const barData = {{
            labels: {bar_labels},
            datasets: [{{
                label: 'Number of Files',
                data: {bar_data},
                backgroundColor: '{bar_color}',
                borderColor: '{bar_border_color}',
                borderWidth: 1
            }}]
        }};

        // Initialize charts
        new Chart(document.getElementById('pieChart'), {{
            type: 'pie',
            data: pieData,
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});

        new Chart(document.getElementById('barChart'), {{
            type: 'bar',
            data: barData,
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});
    </script>
</body>
</html>"#,
        total = analysis.total_files,
        pie_labels = pie_labels_json,
        pie_data = pie_data_json,
        pie_colors = pie_colors_json,
        bar_labels = bar_labels_json,
        bar_data = bar_data_json,
        bar_color = bar_color,
        bar_border_color = bar_border_color
    )
}
