# File Analyzer

A Rust-based CLI tool to analyze GitHub repositories. It clones a repository, analyzes its file structure (categorizing by code, static assets, configuration, etc.), and generates a detailed HTML report.

## Features

- **Clone & Analyze**: Automatically clones a GitHub repository (supports `https://` and `git@` protocols).
- **Security Validations**: Validates repository URLs and sanitizes repository names to prevent path traversal and other dangerous behaviors.
- **File Categorization**: Classifies files into:
  - **Code**: Rust, Python, JavaScript, TypeScript, C/C++, Java, Go, etc.
  - **Static Assets**: HTML, CSS, Images (JPG, PNG, SVG), WebP, etc.
  - **Configuration**: YAML, JSON, TOML, XML, etc.
- **HTML Report Generation**: Produces a clean `report.html` summarizing:
  - Total file count.
  - Breakdown by category.
  - Language distribution within the code category.
- **Auto-Cleanup**: Automatically removes the cloned repository after analysis.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (Cargo)
- [Git](https://git-scm.com/downloads) installed and available in your PATH.

## Installation

1. Clone this repository:
   ```bash
   git clone <this-repo-url>
   cd file_analyzer
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

## Usage

Run the analyzer by providing a GitHub repository URL:

```bash
cargo run -- --repo https://github.com/username/repository
```

Or using the compiled binary:

```bash
./target/release/file_analyzer --repo git@github.com:username/repository.git
```

### Command Line Arguments

| Argument | Short | Description |
| :--- | :--- | :--- |
| `--repo` | `-r` | **Required**. The GitHub repository URL to analyze. |
| `--help` | `-h` | Print help information. |
| `--version` | `-V` | Print version information. |

## Output

After execution, a file named `report.html` will be generated in the root directory. This report provides a visual summary of the repository's contents.

## Project Structure

- `src/main.rs`: Core logic for cloning, analyzing files, and generating reports.
- `Cargo.toml`: Project dependencies and configuration.

## Dependencies

- [clap](https://crates.io/crates/clap): Command-line argument parsing.
- [walkdir](https://crates.io/crates/walkdir): Efficient recursive directory traversal.
- [serde](https://crates.io/crates/serde) & [serde_json](https://crates.io/crates/serde_json): Serialization for analysis data.
- [reqwest](https://crates.io/crates/reqwest): HTTP client (prepared for future extensions).

## License

MIT (or your preferred license)
