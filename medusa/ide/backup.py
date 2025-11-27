#!/usr/bin/env python3
"""
MEDUSA IDE Backup Manager

Backs up user config files before MEDUSA modifies them, allowing rollback.

Backup location: ~/.medusa/backups/{project-name}/{timestamp}/
"""

import os
import shutil
import json
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Tuple


class IDEBackupManager:
    """Manages backups of IDE configuration files"""

    # Files that MEDUSA might modify/create
    TRACKED_FILES = [
        'CLAUDE.md',
        'GEMINI.md',
        'AGENTS.md',
        '.github/copilot-instructions.md',
        '.cursor/mcp.json',
        '.claude/commands/medusa-scan.md',
        '.claude/commands/medusa-install.md',
        '.claude/agents/medusa/agent.json',
        '.gemini/commands/medusa-scan.toml',
        '.gemini/commands/medusa-install.toml',
    ]

    def __init__(self, project_root: Path):
        self.project_root = project_root.absolute()
        self.project_name = self.project_root.name
        self.backup_base = Path.home() / ".medusa" / "backups" / self.project_name
        self.backup_base.mkdir(parents=True, exist_ok=True)
        self.current_backup_dir: Optional[Path] = None
        self.backed_up_files: List[str] = []

    def _get_timestamp(self) -> str:
        """Generate timestamp for backup folder"""
        return datetime.now().strftime('%Y-%m-%d-%H%M%S')

    def start_backup_session(self) -> Path:
        """Start a new backup session, returns backup directory"""
        timestamp = self._get_timestamp()
        self.current_backup_dir = self.backup_base / timestamp
        self.current_backup_dir.mkdir(parents=True, exist_ok=True)
        self.backed_up_files = []

        # Save metadata
        metadata = {
            'timestamp': timestamp,
            'project_root': str(self.project_root),
            'project_name': self.project_name,
            'created_at': datetime.now().isoformat(),
            'files': []
        }
        self._save_metadata(metadata)

        return self.current_backup_dir

    def backup_file(self, relative_path: str) -> bool:
        """
        Backup a single file if it exists.

        Args:
            relative_path: Path relative to project root (e.g., 'CLAUDE.md')

        Returns:
            True if file was backed up, False if file didn't exist
        """
        if self.current_backup_dir is None:
            self.start_backup_session()

        source = self.project_root / relative_path

        if not source.exists():
            return False

        # Create parent directories in backup
        dest = self.current_backup_dir / relative_path
        dest.parent.mkdir(parents=True, exist_ok=True)

        # Copy file
        shutil.copy2(source, dest)
        self.backed_up_files.append(relative_path)

        # Update metadata
        self._update_metadata_files()

        return True

    def backup_if_exists(self, relative_path: str) -> Tuple[bool, Optional[Path]]:
        """
        Backup file if it exists, return status and backup path.

        Returns:
            Tuple of (was_backed_up, backup_path)
        """
        backed_up = self.backup_file(relative_path)
        if backed_up and self.current_backup_dir:
            return (True, self.current_backup_dir / relative_path)
        return (False, None)

    def backup_all_tracked(self) -> List[str]:
        """
        Backup all tracked files that exist.

        Returns:
            List of files that were backed up
        """
        backed_up = []
        for file_path in self.TRACKED_FILES:
            if self.backup_file(file_path):
                backed_up.append(file_path)
        return backed_up

    def _save_metadata(self, metadata: Dict):
        """Save backup metadata"""
        if self.current_backup_dir:
            metadata_file = self.current_backup_dir / 'backup_metadata.json'
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

    def _update_metadata_files(self):
        """Update the files list in metadata"""
        if self.current_backup_dir:
            metadata_file = self.current_backup_dir / 'backup_metadata.json'
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                metadata['files'] = self.backed_up_files
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)

    def list_backups(self) -> List[Dict]:
        """
        List all backups for this project.

        Returns:
            List of backup info dicts, sorted by date (newest first)
        """
        backups = []

        if not self.backup_base.exists():
            return backups

        for backup_dir in sorted(self.backup_base.iterdir(), reverse=True):
            if not backup_dir.is_dir():
                continue

            metadata_file = backup_dir / 'backup_metadata.json'
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    metadata['backup_dir'] = str(backup_dir)
                    backups.append(metadata)
                except (json.JSONDecodeError, IOError):
                    # Fallback if metadata is corrupted
                    backups.append({
                        'timestamp': backup_dir.name,
                        'backup_dir': str(backup_dir),
                        'files': list(backup_dir.rglob('*'))
                    })
            else:
                # No metadata, just list files
                files = [str(f.relative_to(backup_dir)) for f in backup_dir.rglob('*') if f.is_file()]
                backups.append({
                    'timestamp': backup_dir.name,
                    'backup_dir': str(backup_dir),
                    'files': files
                })

        return backups

    def restore_backup(self, timestamp: Optional[str] = None, dry_run: bool = False) -> List[Tuple[str, str]]:
        """
        Restore files from a backup.

        Args:
            timestamp: Specific backup to restore (default: most recent)
            dry_run: If True, just return what would be restored

        Returns:
            List of (source, destination) tuples for restored files
        """
        backups = self.list_backups()

        if not backups:
            raise ValueError(f"No backups found for project '{self.project_name}'")

        # Find the backup to restore
        backup_info = None
        if timestamp:
            for b in backups:
                if b.get('timestamp') == timestamp:
                    backup_info = b
                    break
            if not backup_info:
                raise ValueError(f"Backup '{timestamp}' not found")
        else:
            # Most recent
            backup_info = backups[0]

        backup_dir = Path(backup_info['backup_dir'])
        restored = []

        # Find all files in backup (excluding metadata)
        for backup_file in backup_dir.rglob('*'):
            if backup_file.is_file() and backup_file.name != 'backup_metadata.json':
                relative_path = backup_file.relative_to(backup_dir)
                dest = self.project_root / relative_path

                if not dry_run:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(backup_file, dest)

                restored.append((str(backup_file), str(dest)))

        return restored

    def get_backup_path(self) -> Optional[Path]:
        """Get current backup session directory"""
        return self.current_backup_dir

    def cleanup_old_backups(self, keep_count: int = 10):
        """
        Remove old backups, keeping only the most recent ones.

        Args:
            keep_count: Number of backups to keep
        """
        backups = self.list_backups()

        if len(backups) <= keep_count:
            return

        # Remove oldest backups
        for backup in backups[keep_count:]:
            backup_dir = Path(backup['backup_dir'])
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
