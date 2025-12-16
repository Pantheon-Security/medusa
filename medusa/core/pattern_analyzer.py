#!/usr/bin/env python3
"""
MEDUSA CodePatternAnalyzer - Proprietary Pre-Scanner

This is MEDUSA's core differentiator:
1. Detects file types (for smart scanner selection)
2. Identifies frameworks and patterns (for context)
3. Extracts security context (for false positive filtering)
4. Recommends which scanners to run (for efficiency)

Pure Python - no external dependencies required.
"""

import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import json


@dataclass
class SecurityContext:
    """Security-relevant patterns found in the codebase"""
    # ORM usage reduces SQL injection risk
    uses_orm: bool = False
    orm_frameworks: Set[str] = field(default_factory=set)

    # Parameterized queries reduce SQL injection risk
    uses_parameterized_queries: bool = False

    # Input validation reduces injection risks
    has_input_validation: bool = False
    validation_patterns: Set[str] = field(default_factory=set)

    # Authentication patterns
    authentication_patterns: Set[str] = field(default_factory=set)

    # Test directories (lower severity for test code)
    test_directories: Set[str] = field(default_factory=set)

    # CI/CD config present (code is likely reviewed)
    has_ci_config: bool = False
    ci_systems: Set[str] = field(default_factory=set)

    # Security headers/middleware
    has_security_middleware: bool = False
    security_patterns: Set[str] = field(default_factory=set)

    # AI/LLM patterns (triggers AI security scanners)
    has_ai_patterns: bool = False
    ai_frameworks: Set[str] = field(default_factory=set)
    has_mcp_config: bool = False
    has_rag_patterns: bool = False
    has_agent_patterns: bool = False


@dataclass
class RepoAnalysis:
    """Complete analysis of a repository"""
    # File inventory
    languages: Dict[str, int] = field(default_factory=dict)
    file_extensions: Dict[str, int] = field(default_factory=dict)
    total_files: int = 0

    # Framework detection
    frameworks: Set[str] = field(default_factory=set)
    package_managers: Set[str] = field(default_factory=set)

    # Security context
    security_context: SecurityContext = field(default_factory=SecurityContext)

    # Scanner recommendations
    recommended_scanners: Set[str] = field(default_factory=set)
    skip_scanners: Set[str] = field(default_factory=set)

    # Files requiring AI security scanning
    ai_security_files: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dictionary"""
        return {
            'languages': dict(self.languages),
            'file_extensions': dict(self.file_extensions),
            'total_files': self.total_files,
            'frameworks': list(self.frameworks),
            'package_managers': list(self.package_managers),
            'security_context': {
                'uses_orm': self.security_context.uses_orm,
                'orm_frameworks': list(self.security_context.orm_frameworks),
                'uses_parameterized_queries': self.security_context.uses_parameterized_queries,
                'has_input_validation': self.security_context.has_input_validation,
                'validation_patterns': list(self.security_context.validation_patterns),
                'authentication_patterns': list(self.security_context.authentication_patterns),
                'test_directories': list(self.security_context.test_directories),
                'has_ci_config': self.security_context.has_ci_config,
                'ci_systems': list(self.security_context.ci_systems),
                'has_security_middleware': self.security_context.has_security_middleware,
                'security_patterns': list(self.security_context.security_patterns),
                'has_ai_patterns': self.security_context.has_ai_patterns,
                'ai_frameworks': list(self.security_context.ai_frameworks),
                'has_mcp_config': self.security_context.has_mcp_config,
                'has_rag_patterns': self.security_context.has_rag_patterns,
                'has_agent_patterns': self.security_context.has_agent_patterns,
            },
            'recommended_scanners': list(self.recommended_scanners),
            'skip_scanners': list(self.skip_scanners),
            'ai_security_files': self.ai_security_files[:50],  # Limit for display
        }


class CodePatternAnalyzer:
    """
    MEDUSA's proprietary code pattern analyzer.

    This analyzer runs BEFORE any external tools, providing:
    1. Smart scanner selection (only install what's needed)
    2. Security context for false positive filtering
    3. AI/Agent pattern detection for specialized scanning
    """

    # Extension to language mapping
    EXTENSION_TO_LANGUAGE = {
        '.py': 'python',
        '.pyw': 'python',
        '.pyx': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.php': 'php',
        '.java': 'java',
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        '.scala': 'scala',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.c': 'c',
        '.h': 'c',
        '.hpp': 'cpp',
        '.swift': 'swift',
        '.m': 'objectivec',
        '.mm': 'objectivec',
        '.pl': 'perl',
        '.pm': 'perl',
        '.sh': 'bash',
        '.bash': 'bash',
        '.zsh': 'bash',
        '.ps1': 'powershell',
        '.psm1': 'powershell',
        '.bat': 'batch',
        '.cmd': 'batch',
        '.lua': 'lua',
        '.r': 'r',
        '.R': 'r',
        '.ex': 'elixir',
        '.exs': 'elixir',
        '.erl': 'erlang',
        '.hrl': 'erlang',
        '.hs': 'haskell',
        '.clj': 'clojure',
        '.cljs': 'clojure',
        '.dart': 'dart',
        '.groovy': 'groovy',
        '.sol': 'solidity',
        '.zig': 'zig',
        '.vue': 'vue',
        '.svelte': 'svelte',
        # Config/data formats
        '.yml': 'yaml',
        '.yaml': 'yaml',
        '.json': 'json',
        '.toml': 'toml',
        '.xml': 'xml',
        '.ini': 'ini',
        '.cfg': 'config',
        '.conf': 'config',
        '.env': 'env',
        '.properties': 'properties',
        # Infrastructure
        '.tf': 'terraform',
        '.hcl': 'terraform',
        '.dockerfile': 'docker',
        # Web
        '.html': 'html',
        '.htm': 'html',
        '.css': 'css',
        '.scss': 'css',
        '.sass': 'css',
        '.less': 'css',
        '.sql': 'sql',
        '.graphql': 'graphql',
        '.gql': 'graphql',
        '.proto': 'protobuf',
        '.md': 'markdown',
        '.rst': 'markdown',
    }

    # Language to scanner mapping
    LANGUAGE_TO_SCANNER = {
        'python': 'PythonScanner',
        'javascript': 'JavaScriptScanner',
        'typescript': 'TypeScriptScanner',
        'go': 'GoScanner',
        'rust': 'RustScanner',
        'ruby': 'RubyScanner',
        'php': 'PHPScanner',
        'java': 'JavaScanner',
        'kotlin': 'KotlinScanner',
        'scala': 'ScalaScanner',
        'csharp': 'CSharpScanner',
        'cpp': 'CppScanner',
        'c': 'CppScanner',
        'swift': 'SwiftScanner',
        'perl': 'PerlScanner',
        'bash': 'BashScanner',
        'powershell': 'PowerShellScanner',
        'batch': 'BatScanner',
        'lua': 'LuaScanner',
        'r': 'RScanner',
        'elixir': 'ElixirScanner',
        'haskell': 'HaskellScanner',
        'clojure': 'ClojureScanner',
        'dart': 'DartScanner',
        'groovy': 'GroovyScanner',
        'solidity': 'SolidityScanner',
        'zig': 'ZigScanner',
        'yaml': 'YAMLScanner',
        'json': 'JSONScanner',
        'toml': 'TOMLScanner',
        'xml': 'XMLScanner',
        'env': 'EnvScanner',
        'terraform': 'TerraformScanner',
        'docker': 'DockerScanner',
        'html': 'HTMLScanner',
        'css': 'CSSScanner',
        'sql': 'SQLScanner',
        'graphql': 'GraphQLScanner',
        'protobuf': 'ProtobufScanner',
        'markdown': 'MarkdownScanner',
    }

    # Scanner class name to CLI tool name mapping
    SCANNER_TO_TOOL = {
        'PythonScanner': 'bandit',
        'JavaScriptScanner': 'eslint',
        'TypeScriptScanner': 'eslint',
        'GoScanner': 'golangci-lint',
        'RustScanner': 'cargo-audit',
        'RubyScanner': 'rubocop',
        'PHPScanner': 'phpstan',
        'JavaScanner': 'spotbugs',
        'KotlinScanner': 'detekt',
        'ScalaScanner': 'scalastyle',
        'CppScanner': 'cppcheck',
        'SwiftScanner': 'swiftlint',
        'PerlScanner': 'perlcritic',
        'BashScanner': 'shellcheck',
        'PowerShellScanner': 'psscriptanalyzer',
        'BatScanner': 'Blinter',
        'LuaScanner': 'luacheck',
        'RScanner': 'lintr',
        'ElixirScanner': 'credo',
        'HaskellScanner': 'hlint',
        'ClojureScanner': 'clj-kondo',
        'DartScanner': 'dart',
        'GroovyScanner': 'groovy',
        'SolidityScanner': 'slither',
        'ZigScanner': 'zig',
        'YAMLScanner': 'yamllint',
        'JSONScanner': 'jsonlint',
        'TOMLScanner': 'taplo',
        'XMLScanner': 'xmllint',
        'EnvScanner': None,  # Built-in, no external tool
        'TerraformScanner': 'tflint',
        'DockerScanner': 'hadolint',
        'HTMLScanner': 'htmlhint',
        'CSSScanner': 'stylelint',
        'SQLScanner': 'sqlfluff',
        'GraphQLScanner': 'graphql-schema-linter',
        'ProtobufScanner': 'buf',
        'MarkdownScanner': 'markdownlint',
        # AI Security Scanners (built-in, no external tools)
        'MCPConfigScanner': None,
        'MCPServerScanner': None,
        'AIContextScanner': None,
        'AgentMemoryScanner': None,
        'RAGSecurityScanner': None,
        'A2AScanner': None,
        'PromptLeakageScanner': None,
        'ToolCallbackScanner': None,
        'OWASPLLMScanner': None,
        'ModelAttackScanner': None,
        'MultiAgentScanner': None,
        'LLMOpsScanner': None,
        # External tool integrations
        'GitLeaksScanner': 'gitleaks',
        'TrivyScanner': 'trivy',
        'SemgrepScanner': 'semgrep',
    }

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        # Python
        'django': [r'from django', r'import django', r'DJANGO_SETTINGS_MODULE'],
        'flask': [r'from flask import', r'Flask\(__name__\)'],
        'fastapi': [r'from fastapi import', r'FastAPI\(\)'],
        'pytorch': [r'import torch', r'from torch'],
        'tensorflow': [r'import tensorflow', r'from tensorflow'],
        'langchain': [r'from langchain', r'import langchain'],
        'llama_index': [r'from llama_index', r'import llama_index'],
        'openai_sdk': [r'from openai import', r'import openai', r'OpenAI\(\)'],
        'anthropic_sdk': [r'from anthropic import', r'import anthropic', r'Anthropic\(\)'],
        'transformers': [r'from transformers import', r'import transformers'],

        # JavaScript/TypeScript
        'react': [r'from [\'"]react[\'"]', r'import React', r'React\.'],
        'vue': [r'from [\'"]vue[\'"]', r'createApp', r'Vue\.'],
        'angular': [r'@angular/', r'@Component'],
        'express': [r'from [\'"]express[\'"]', r'express\(\)'],
        'nextjs': [r'from [\'"]next', r'next/'],
        'nestjs': [r'@nestjs/', r'@Module'],

        # AI/LLM specific
        'mcp_server': [r'@server\.', r'mcp\.server', r'MCPServer', r'create_server'],
        'mcp_client': [r'mcp\.client', r'MCPClient'],
        'crewai': [r'from crewai', r'import crewai'],
        'autogen': [r'from autogen', r'import autogen'],

        # Infrastructure
        'kubernetes': [r'apiVersion:', r'kind:\s*(Pod|Deployment|Service)'],
        'docker_compose': [r'services:', r'docker-compose'],
        'ansible': [r'ansible\.', r'- hosts:', r'- name:.*\n\s+'],
    }

    # ORM patterns (reduces SQL injection FP)
    ORM_PATTERNS = {
        'sqlalchemy': [r'from sqlalchemy', r'Session\(\)', r'Base\.metadata'],
        'django_orm': [r'\.objects\.', r'\.filter\(', r'\.get\(', r'models\.Model'],
        'prisma': [r'@prisma/client', r'prisma\.'],
        'sequelize': [r'sequelize', r'Model\.findAll'],
        'typeorm': [r'@Entity', r'Repository<'],
        'mongoose': [r'mongoose\.Schema', r'mongoose\.model'],
        'peewee': [r'from peewee', r'Model\.select'],
        'tortoise': [r'from tortoise', r'tortoise\.models'],
    }

    # Input validation patterns (reduces injection FP)
    VALIDATION_PATTERNS = {
        'pydantic': [r'from pydantic', r'BaseModel', r'validator'],
        'marshmallow': [r'from marshmallow', r'Schema'],
        'cerberus': [r'from cerberus', r'Validator'],
        'joi': [r'Joi\.', r'\.validate\('],
        'zod': [r'from [\'"]zod[\'"]', r'z\.string', r'z\.object'],
        'yup': [r'from [\'"]yup[\'"]', r'yup\.string'],
        'class_validator': [r'class-validator', r'@IsString', r'@IsEmail'],
        'wtforms': [r'from wtforms', r'StringField', r'validators'],
    }

    # Authentication patterns
    AUTH_PATTERNS = {
        'jwt': [r'jwt\.', r'jsonwebtoken', r'PyJWT', r'jose'],
        'oauth': [r'oauth', r'OAuth2', r'client_credentials'],
        'passport': [r'passport\.', r'passport-'],
        'session': [r'session\[', r'req\.session', r'flask\.session'],
        'api_key': [r'api_key', r'apiKey', r'API_KEY', r'x-api-key'],
        'basic_auth': [r'BasicAuth', r'basic_auth', r'Authorization.*Basic'],
        'firebase_auth': [r'firebase.*auth', r'FirebaseAuth'],
        'auth0': [r'auth0', r'@auth0'],
    }

    # Security middleware/headers patterns
    SECURITY_PATTERNS = {
        'cors': [r'CORS\(', r'cors\(', r'Access-Control-'],
        'helmet': [r'helmet\(', r'from helmet'],
        'csrf': [r'csrf', r'CSRF', r'_token'],
        'rate_limit': [r'rate.?limit', r'RateLimit', r'throttle'],
        'xss_protection': [r'escape\(', r'sanitize', r'DOMPurify'],
        'content_security_policy': [r'Content-Security-Policy', r'CSP'],
        'secure_headers': [r'Strict-Transport-Security', r'X-Frame-Options'],
    }

    # AI/Agent specific patterns that need AI security scanning
    AI_PATTERNS = {
        'prompt_template': [r'PromptTemplate', r'prompt_template', r'system_prompt'],
        'chat_completion': [r'chat\.completions', r'ChatCompletion', r'messages\s*='],
        'embedding': [r'\.embed', r'Embedding', r'get_embedding'],
        'vector_store': [r'VectorStore', r'Pinecone', r'Chroma', r'Weaviate', r'Qdrant', r'FAISS'],
        'retriever': [r'Retriever', r'\.retrieve\(', r'similarity_search'],
        'agent': [r'Agent\(', r'create_agent', r'AgentExecutor', r'\.run\('],
        'tool_use': [r'@tool', r'Tool\(', r'tools\s*=', r'function_call'],
        'memory': [r'ConversationMemory', r'ChatMemory', r'\.memory'],
        'chain': [r'LLMChain', r'SequentialChain', r'\.chain'],
        'mcp_config': [r'mcpServers', r'mcp-config', r'claude_desktop_config'],
    }

    # CI/CD configuration files
    CI_CONFIG_FILES = {
        '.github/workflows': 'github_actions',
        '.gitlab-ci.yml': 'gitlab_ci',
        'Jenkinsfile': 'jenkins',
        '.circleci': 'circleci',
        'azure-pipelines.yml': 'azure_devops',
        '.travis.yml': 'travis',
        'bitbucket-pipelines.yml': 'bitbucket',
        '.drone.yml': 'drone',
    }

    # Package manager files
    PACKAGE_MANAGER_FILES = {
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'pnpm-lock.yaml': 'pnpm',
        'requirements.txt': 'pip',
        'Pipfile': 'pipenv',
        'Pipfile.lock': 'pipenv',
        'pyproject.toml': 'poetry',
        'poetry.lock': 'poetry',
        'setup.py': 'pip',
        'Gemfile': 'bundler',
        'Gemfile.lock': 'bundler',
        'go.mod': 'go_modules',
        'go.sum': 'go_modules',
        'Cargo.toml': 'cargo',
        'Cargo.lock': 'cargo',
        'composer.json': 'composer',
        'composer.lock': 'composer',
        'pom.xml': 'maven',
        'build.gradle': 'gradle',
        'build.gradle.kts': 'gradle',
    }

    # Directories to skip during analysis
    SKIP_DIRECTORIES = {
        'node_modules', '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
        '.mypy_cache', '.tox', '.nox', 'venv', '.venv', 'env', '.env',
        'virtualenv', 'dist', 'build', 'target', 'bin', 'obj',
        '.idea', '.vscode', '.vs', 'vendor', 'bower_components',
        'site-packages', 'dist-packages', '.cache', 'coverage',
        'htmlcov', '.eggs', '*.egg-info', 'wheels',
    }

    def __init__(self, max_file_size: int = 1_000_000, sample_lines: int = 100):
        """
        Initialize the analyzer.

        Args:
            max_file_size: Maximum file size to analyze (bytes)
            sample_lines: Number of lines to sample from large files
        """
        self.max_file_size = max_file_size
        self.sample_lines = sample_lines

    def analyze_repo(self, path: Path) -> RepoAnalysis:
        """
        Analyze a repository and return comprehensive analysis.

        Args:
            path: Path to repository root

        Returns:
            RepoAnalysis with file inventory, frameworks, and security context
        """
        analysis = RepoAnalysis()
        analysis.security_context = SecurityContext()

        path = Path(path).resolve()

        # Walk the repository
        for file_path in self._walk_repo(path):
            self._analyze_file(file_path, path, analysis)

        # Detect CI/CD
        self._detect_ci_config(path, analysis)

        # Detect package managers
        self._detect_package_managers(path, analysis)

        # Detect test directories
        self._detect_test_directories(path, analysis)

        # Determine recommended scanners
        self._recommend_scanners(analysis)

        return analysis

    def _walk_repo(self, path: Path):
        """Walk repository, skipping excluded directories"""
        for item in path.iterdir():
            if item.name in self.SKIP_DIRECTORIES:
                continue
            if item.name.startswith('.') and item.name not in {'.github', '.gitlab-ci.yml'}:
                continue

            if item.is_file():
                yield item
            elif item.is_dir():
                yield from self._walk_repo(item)

    def _analyze_file(self, file_path: Path, repo_root: Path, analysis: RepoAnalysis):
        """Analyze a single file"""
        # Count file extension
        ext = file_path.suffix.lower()
        if not ext and file_path.name.lower() == 'dockerfile':
            ext = '.dockerfile'

        analysis.file_extensions[ext] = analysis.file_extensions.get(ext, 0) + 1
        analysis.total_files += 1

        # Map to language
        language = self.EXTENSION_TO_LANGUAGE.get(ext)
        if language:
            analysis.languages[language] = analysis.languages.get(language, 0) + 1

        # Read file content for pattern analysis
        content = self._read_file_sample(file_path)
        if not content:
            return

        # Detect frameworks
        self._detect_frameworks(content, analysis)

        # Detect ORM usage
        self._detect_orm(content, analysis)

        # Detect validation patterns
        self._detect_validation(content, analysis)

        # Detect authentication patterns
        self._detect_auth(content, analysis)

        # Detect security patterns
        self._detect_security_patterns(content, analysis)

        # Detect AI patterns
        self._detect_ai_patterns(content, file_path, repo_root, analysis)

    def _read_file_sample(self, file_path: Path) -> Optional[str]:
        """Read file content, sampling for large files"""
        try:
            size = file_path.stat().st_size
            if size > self.max_file_size:
                # Sample from file
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = []
                    for i, line in enumerate(f):
                        if i >= self.sample_lines:
                            break
                        lines.append(line)
                    return ''.join(lines)
            else:
                return file_path.read_text(encoding='utf-8', errors='ignore')
        except (OSError, IOError, PermissionError):
            return None

    def _detect_frameworks(self, content: str, analysis: RepoAnalysis):
        """Detect frameworks from content"""
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.frameworks.add(framework)
                    break

    def _detect_orm(self, content: str, analysis: RepoAnalysis):
        """Detect ORM usage"""
        for orm, patterns in self.ORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    analysis.security_context.uses_orm = True
                    analysis.security_context.orm_frameworks.add(orm)
                    break

        # Check for parameterized queries
        parameterized_patterns = [
            r'\?\s*,',  # ? placeholders
            r'%s',  # Python DB-API
            r'\$\d+',  # PostgreSQL
            r':\w+',  # Named parameters
            r'@\w+',  # SQL Server named
        ]
        for pattern in parameterized_patterns:
            if re.search(pattern, content):
                analysis.security_context.uses_parameterized_queries = True
                break

    def _detect_validation(self, content: str, analysis: RepoAnalysis):
        """Detect input validation patterns"""
        for validator, patterns in self.VALIDATION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    analysis.security_context.has_input_validation = True
                    analysis.security_context.validation_patterns.add(validator)
                    break

    def _detect_auth(self, content: str, analysis: RepoAnalysis):
        """Detect authentication patterns"""
        for auth_type, patterns in self.AUTH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.security_context.authentication_patterns.add(auth_type)
                    break

    def _detect_security_patterns(self, content: str, analysis: RepoAnalysis):
        """Detect security middleware and patterns"""
        for sec_pattern, patterns in self.SECURITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.security_context.has_security_middleware = True
                    analysis.security_context.security_patterns.add(sec_pattern)
                    break

    def _detect_ai_patterns(self, content: str, file_path: Path, repo_root: Path, analysis: RepoAnalysis):
        """Detect AI/LLM patterns that need AI security scanning"""
        for pattern_name, patterns in self.AI_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.security_context.has_ai_patterns = True
                    analysis.security_context.ai_frameworks.add(pattern_name)

                    # Track specific AI pattern types
                    if pattern_name == 'mcp_config':
                        analysis.security_context.has_mcp_config = True
                    if pattern_name in ['retriever', 'vector_store', 'embedding']:
                        analysis.security_context.has_rag_patterns = True
                    if pattern_name in ['agent', 'tool_use', 'memory']:
                        analysis.security_context.has_agent_patterns = True

                    # Add to AI security files list
                    rel_path = str(file_path.relative_to(repo_root))
                    if rel_path not in analysis.ai_security_files:
                        analysis.ai_security_files.append(rel_path)
                    break

    def _detect_ci_config(self, path: Path, analysis: RepoAnalysis):
        """Detect CI/CD configuration"""
        for ci_path, ci_system in self.CI_CONFIG_FILES.items():
            check_path = path / ci_path
            if check_path.exists():
                analysis.security_context.has_ci_config = True
                analysis.security_context.ci_systems.add(ci_system)

    def _detect_package_managers(self, path: Path, analysis: RepoAnalysis):
        """Detect package managers in use"""
        for pm_file, pm_name in self.PACKAGE_MANAGER_FILES.items():
            if (path / pm_file).exists():
                analysis.package_managers.add(pm_name)

    def _detect_test_directories(self, path: Path, analysis: RepoAnalysis):
        """Detect test directories"""
        test_dir_names = {'tests', 'test', '__tests__', 'spec', 'specs', 'testing'}
        for item in path.iterdir():
            if item.is_dir() and item.name.lower() in test_dir_names:
                analysis.security_context.test_directories.add(str(item.relative_to(path)))

    def _recommend_scanners(self, analysis: RepoAnalysis):
        """Determine which scanners to run and which to skip"""
        # Get all available scanner types
        all_scanner_types = set(self.LANGUAGE_TO_SCANNER.values())

        # Recommend scanners based on detected languages
        for language, count in analysis.languages.items():
            scanner = self.LANGUAGE_TO_SCANNER.get(language)
            if scanner:
                analysis.recommended_scanners.add(scanner)

        # Always recommend these if AI patterns detected
        if analysis.security_context.has_ai_patterns:
            ai_scanners = {
                'MCPConfigScanner', 'MCPServerScanner', 'AIContextScanner',
                'AgentMemoryScanner', 'RAGSecurityScanner', 'A2AScanner',
                'PromptLeakageScanner', 'ToolCallbackScanner', 'OWASPLLMScanner',
                'ModelAttackScanner', 'MultiAgentScanner', 'LLMOpsScanner',
            }
            analysis.recommended_scanners.update(ai_scanners)

        # Always recommend secret detection
        analysis.recommended_scanners.add('GitLeaksScanner')
        analysis.recommended_scanners.add('EnvScanner')

        # Recommend Trivy if package managers detected
        if analysis.package_managers:
            analysis.recommended_scanners.add('TrivyScanner')

        # Skip scanners for languages not present
        for language, scanner in self.LANGUAGE_TO_SCANNER.items():
            if language not in analysis.languages and scanner in all_scanner_types:
                # Only skip if not already recommended
                if scanner not in analysis.recommended_scanners:
                    analysis.skip_scanners.add(scanner)

    def get_fp_context(self, analysis: RepoAnalysis, finding: dict) -> dict:
        """
        Get false positive context for a specific finding.

        This helps determine if a finding is likely a false positive
        based on the security context of the codebase.

        Args:
            analysis: RepoAnalysis from analyze_repo()
            finding: A security finding dictionary

        Returns:
            Dictionary with FP likelihood indicators
        """
        context = {
            'likely_false_positive': False,
            'confidence_reduction': 0,  # 0-100, higher = more likely FP
            'reasons': [],
        }

        rule_id = finding.get('rule_id', '').upper()
        message = finding.get('message', '').lower()
        file_path = finding.get('file', '')

        # SQL injection with ORM usage
        if 'sql' in message or 'injection' in message:
            if analysis.security_context.uses_orm:
                context['confidence_reduction'] += 40
                context['reasons'].append(f"ORM in use: {', '.join(analysis.security_context.orm_frameworks)}")
            if analysis.security_context.uses_parameterized_queries:
                context['confidence_reduction'] += 30
                context['reasons'].append("Parameterized queries detected")

        # Input validation reduces injection risks
        if any(x in message for x in ['injection', 'xss', 'input']):
            if analysis.security_context.has_input_validation:
                context['confidence_reduction'] += 25
                context['reasons'].append(f"Validation: {', '.join(analysis.security_context.validation_patterns)}")

        # Test code gets lower priority
        for test_dir in analysis.security_context.test_directories:
            if test_dir in file_path:
                context['confidence_reduction'] += 50
                context['reasons'].append(f"Located in test directory: {test_dir}")
                break

        # Security middleware suggests security awareness
        if analysis.security_context.has_security_middleware:
            context['confidence_reduction'] += 10
            context['reasons'].append("Security middleware detected")

        # Determine if likely FP
        if context['confidence_reduction'] >= 50:
            context['likely_false_positive'] = True

        return context

    def get_recommended_tools(self, analysis: RepoAnalysis) -> Set[str]:
        """
        Get the list of external tools recommended for installation.

        Args:
            analysis: RepoAnalysis from analyze_repo()

        Returns:
            Set of tool names (e.g., 'bandit', 'eslint') that should be installed
        """
        tools = set()
        for scanner_name in analysis.recommended_scanners:
            tool = self.SCANNER_TO_TOOL.get(scanner_name)
            if tool:  # Skip None (built-in scanners)
                tools.add(tool)
        return tools

    def get_skipped_tools(self, analysis: RepoAnalysis) -> Set[str]:
        """
        Get the list of external tools that can be skipped (not needed).

        Args:
            analysis: RepoAnalysis from analyze_repo()

        Returns:
            Set of tool names that are not needed for this project
        """
        tools = set()
        for scanner_name in analysis.skip_scanners:
            tool = self.SCANNER_TO_TOOL.get(scanner_name)
            if tool:  # Skip None (built-in scanners)
                tools.add(tool)
        return tools


def analyze_directory(path: str) -> dict:
    """
    Convenience function to analyze a directory.

    Args:
        path: Path to directory

    Returns:
        Dictionary with analysis results
    """
    analyzer = CodePatternAnalyzer()
    analysis = analyzer.analyze_repo(Path(path))
    return analysis.to_dict()


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python pattern_analyzer.py <path>")
        sys.exit(1)

    result = analyze_directory(sys.argv[1])
    print(json.dumps(result, indent=2))
