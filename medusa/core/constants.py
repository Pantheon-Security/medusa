"""
MEDUSA shared constants.

Single source of truth for values used across multiple modules.
"""

# Dotfile directories that contain scannable AI/security context.
# Used by both pattern_analyzer._walk_repo and parallel.py file collection.
AI_CONTEXT_DOTDIRS: frozenset = frozenset({
    '.github', '.gitlab', '.cursor', '.claude', '.continue',
})

# Individual dotfiles (not directories) that are scannable AI/security context.
AI_CONTEXT_DOTFILES: frozenset = frozenset({
    '.cursorrules', '.clinerules', '.windsurfrules',
    '.env', '.mcp.json', '.gitlab-ci.yml',
})

# Combined set for quick membership checks in walk logic
AI_CONTEXT_DOTNAMES: frozenset = AI_CONTEXT_DOTDIRS | AI_CONTEXT_DOTFILES
