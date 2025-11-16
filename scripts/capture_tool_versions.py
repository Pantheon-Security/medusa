#!/usr/bin/env python3
"""
MEDUSA Tool Version Capture Script

Queries latest versions of all external tools and generates tool-versions.lock file.
"""

import json
import subprocess
import sys
from datetime import datetime
from typing import Dict, Optional
import requests
from rich.console import Console
from rich.table import Table

console = Console()


class VersionCapture:
    """Captures latest versions of external tools"""

    def __init__(self):
        self.versions = {}

    def get_pip_version(self, package: str) -> Optional[str]:
        """Get latest version from PyPI"""
        try:
            response = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=5)
            if response.ok:
                data = response.json()
                return data['info']['version']
        except Exception as e:
            console.print(f"[yellow]Warning: Could not fetch {package} from PyPI: {e}[/yellow]")
        return None

    def get_npm_version(self, package: str) -> Optional[str]:
        """Get latest version from npm registry"""
        try:
            response = requests.get(f"https://registry.npmjs.org/{package}", timeout=5)
            if response.ok:
                data = response.json()
                return data['dist-tags']['latest']
        except Exception as e:
            console.print(f"[yellow]Warning: Could not fetch {package} from npm: {e}[/yellow]")
        return None

    def get_github_release(self, repo: str) -> Optional[str]:
        """Get latest GitHub release version"""
        try:
            response = requests.get(
                f"https://api.github.com/repos/{repo}/releases/latest",
                timeout=5,
                headers={"Accept": "application/vnd.github.v3+json"}
            )
            if response.ok:
                data = response.json()
                tag = data['tag_name']
                # Strip 'v' prefix if present
                return tag.lstrip('v')
        except Exception as e:
            console.print(f"[yellow]Warning: Could not fetch {repo} from GitHub: {e}[/yellow]")
        return None

    def get_cargo_version(self, package: str) -> Optional[str]:
        """Get latest version from crates.io"""
        try:
            response = requests.get(f"https://crates.io/api/v1/crates/{package}", timeout=5)
            if response.ok:
                data = response.json()
                return data['crate']['max_version']
        except Exception as e:
            console.print(f"[yellow]Warning: Could not fetch {package} from crates.io: {e}[/yellow]")
        return None

    def get_local_version(self, command: str) -> Optional[str]:
        """Get version from local installation"""
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            # Parse version from output (simple heuristic)
            output = result.stdout + result.stderr
            # Look for version patterns like "1.2.3"
            import re
            match = re.search(r'(\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    def capture_all_versions(self) -> Dict:
        """Capture versions for all MEDUSA tools"""

        console.print("\n[bold cyan]Capturing Tool Versions...[/bold cyan]\n")

        tools = {
            # Python tools (PyPI)
            'python': {
                'bandit': ('pip', 'bandit'),
                'yamllint': ('pip', 'yamllint'),
                'sqlfluff': ('pip', 'sqlfluff'),
                'ansible-lint': ('pip', 'ansible-lint'),
                'mypy': ('pip', 'mypy'),
                'pylint': ('pip', 'pylint'),
                'black': ('pip', 'black'),
                'ruff': ('pip', 'ruff'),
                'prospector': ('pip', 'prospector'),
                'pydocstyle': ('pip', 'pydocstyle'),
                'pyflakes': ('pip', 'pyflakes'),
                'mccabe': ('pip', 'mccabe'),
                'vulture': ('pip', 'vulture'),
                'safety': ('pip', 'safety'),
            },
            # JavaScript tools (npm)
            'javascript': {
                'eslint': ('npm', 'eslint'),
                'typescript': ('npm', 'typescript'),
                'markdownlint-cli': ('npm', 'markdownlint-cli'),
                'stylelint': ('npm', 'stylelint'),
                'htmlhint': ('npm', 'htmlhint'),
                'jshint': ('npm', 'jshint'),
                'standard': ('npm', 'standard'),
                'prettier': ('npm', 'prettier'),
            },
            # Go tools (GitHub releases mostly)
            'go': {
                'golangci-lint': ('github', 'golangci/golangci-lint'),
                'staticcheck': ('github', 'dominikh/go-tools'),
            },
            # Rust tools
            'rust': {
                'clippy': ('cargo', 'clippy'),  # Part of rustup
            },
            # Shell tools
            'shell': {
                'shellcheck': ('github', 'koalaman/shellcheck'),
                'bashate': ('pip', 'bashate'),
            },
            # Docker tools
            'docker': {
                'hadolint': ('github', 'hadolint/hadolint'),
            },
            # Terraform tools
            'terraform': {
                'tflint': ('github', 'terraform-linters/tflint'),
                'tfsec': ('github', 'aquasecurity/tfsec'),
                'checkov': ('pip', 'checkov'),
            },
            # Kubernetes tools
            'kubernetes': {
                'kubeval': ('github', 'instrumenta/kubeval'),
                'kube-linter': ('github', 'stackrox/kube-linter'),
            },
            # Other tools
            'misc': {
                'trivy': ('github', 'aquasecurity/trivy'),
                'semgrep': ('pip', 'semgrep'),
                'gitleaks': ('github', 'gitleaks/gitleaks'),
            }
        }

        versions = {
            'metadata': {
                'lockfile_version': '1.0',
                'generated_at': datetime.now().isoformat(),
                'medusa_version': self._get_medusa_version(),
            },
            'tools': {}
        }

        for category, category_tools in tools.items():
            versions['tools'][category] = {}
            console.print(f"[cyan]{category.title()} Tools:[/cyan]")

            for tool_name, (source, identifier) in category_tools.items():
                version = None

                if source == 'pip':
                    version = self.get_pip_version(identifier)
                elif source == 'npm':
                    version = self.get_npm_version(identifier)
                elif source == 'github':
                    version = self.get_github_release(identifier)
                elif source == 'cargo':
                    version = self.get_cargo_version(identifier)

                if version:
                    versions['tools'][category][tool_name] = version
                    console.print(f"  ✓ {tool_name}: {version}")
                else:
                    console.print(f"  ✗ {tool_name}: [yellow]Could not fetch[/yellow]")

            console.print()

        return versions

    def _get_medusa_version(self) -> str:
        """Get current MEDUSA version"""
        try:
            import medusa
            return medusa.__version__
        except:
            return "0.9.0.0"

    def generate_toml_lock_file(self, versions: Dict, output_path: str):
        """Generate TOML format lock file"""

        lines = [
            "# MEDUSA Tool Versions Lock File",
            f"# Generated: {versions['metadata']['generated_at']}",
            f"# MEDUSA Version: {versions['metadata']['medusa_version']}",
            "#",
            "# This file pins specific versions of external security tools to ensure",
            "# reproducible scans across different environments and time periods.",
            "",
            "[metadata]",
            f"lockfile_version = \"{versions['metadata']['lockfile_version']}\"",
            f"generated_at = \"{versions['metadata']['generated_at']}\"",
            f"medusa_version = \"{versions['metadata']['medusa_version']}\"",
            "",
        ]

        for category, tools in versions['tools'].items():
            lines.append(f"[tools.{category}]")
            for tool_name, version in sorted(tools.items()):
                lines.append(f"{tool_name} = \"{version}\"")
            lines.append("")

        content = "\n".join(lines)

        with open(output_path, 'w') as f:
            f.write(content)

        console.print(f"\n[green]✓ Generated lock file:[/green] {output_path}")

    def show_summary_table(self, versions: Dict):
        """Display summary table of captured versions"""

        table = Table(title="Captured Tool Versions")
        table.add_column("Category", style="cyan")
        table.add_column("Tool", style="magenta")
        table.add_column("Version", style="green")

        for category, tools in versions['tools'].items():
            for i, (tool_name, version) in enumerate(sorted(tools.items())):
                cat_display = category.title() if i == 0 else ""
                table.add_row(cat_display, tool_name, version)

        console.print("\n")
        console.print(table)
        console.print(f"\n[bold]Total tools: {sum(len(tools) for tools in versions['tools'].values())}[/bold]")


def main():
    """Main entry point"""

    console.print("[bold cyan]MEDUSA Tool Version Capture[/bold cyan]")
    console.print("Querying latest versions from PyPI, npm, GitHub, etc.\n")

    capturer = VersionCapture()
    versions = capturer.capture_all_versions()

    # Generate lock file
    output_path = "tool-versions.lock"
    capturer.generate_toml_lock_file(versions, output_path)

    # Show summary
    capturer.show_summary_table(versions)

    console.print(f"\n[bold green]✓ Version capture complete![/bold green]")
    console.print(f"[dim]Lock file saved to: {output_path}[/dim]")


if __name__ == "__main__":
    main()
