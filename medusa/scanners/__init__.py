"""
MEDUSA Scanner Heads
76 independent security scanner implementations
"""

from medusa.scanners.base import (
    BaseScanner,
    ScannerRegistry,
    ScannerResult,
    ScannerIssue,
    Severity
)
from medusa.scanners.python_scanner import PythonScanner
from medusa.scanners.bash_scanner import BashScanner
from medusa.scanners.bat_scanner import BatScanner
from medusa.scanners.docker_scanner import DockerScanner
from medusa.scanners.docker_compose_scanner import DockerComposeScanner
from medusa.scanners.markdown_scanner import MarkdownScanner
from medusa.scanners.javascript_scanner import JavaScriptScanner
from medusa.scanners.terraform_scanner import TerraformScanner
from medusa.scanners.go_scanner import GoScanner
from medusa.scanners.json_scanner import JSONScanner
from medusa.scanners.ruby_scanner import RubyScanner
from medusa.scanners.php_scanner import PHPScanner
from medusa.scanners.rust_scanner import RustScanner
from medusa.scanners.sql_scanner import SQLScanner
from medusa.scanners.css_scanner import CSSScanner
from medusa.scanners.html_scanner import HTMLScanner
from medusa.scanners.kotlin_scanner import KotlinScanner
from medusa.scanners.swift_scanner import SwiftScanner
from medusa.scanners.cpp_scanner import CppScanner
from medusa.scanners.java_scanner import JavaScanner
from medusa.scanners.typescript_scanner import TypeScriptScanner
from medusa.scanners.scala_scanner import ScalaScanner
from medusa.scanners.perl_scanner import PerlScanner
from medusa.scanners.powershell_scanner import PowerShellScanner
from medusa.scanners.r_scanner import RScanner
from medusa.scanners.ansible_scanner import AnsibleScanner
from medusa.scanners.kubernetes_scanner import KubernetesScanner
from medusa.scanners.toml_scanner import TOMLScanner
from medusa.scanners.xml_scanner import XMLScanner
from medusa.scanners.protobuf_scanner import ProtobufScanner
from medusa.scanners.graphql_scanner import GraphQLScanner
from medusa.scanners.solidity_scanner import SolidityScanner
from medusa.scanners.lua_scanner import LuaScanner
from medusa.scanners.elixir_scanner import ElixirScanner
from medusa.scanners.haskell_scanner import HaskellScanner
from medusa.scanners.clojure_scanner import ClojureScanner
from medusa.scanners.dart_scanner import DartScanner
from medusa.scanners.groovy_scanner import GroovyScanner
from medusa.scanners.vim_scanner import VimScanner
from medusa.scanners.cmake_scanner import CMakeScanner
from medusa.scanners.make_scanner import MakeScanner
from medusa.scanners.nginx_scanner import NginxScanner
from medusa.scanners.zig_scanner import ZigScanner
from medusa.scanners.env_scanner import EnvScanner
from medusa.scanners.mcp_config_scanner import MCPConfigScanner
from medusa.scanners.mcp_server_scanner import MCPServerScanner
from medusa.scanners.ai_context_scanner import AIContextScanner
from medusa.scanners.agent_memory_scanner import AgentMemoryScanner
from medusa.scanners.rag_security_scanner import RAGSecurityScanner
from medusa.scanners.a2a_scanner import A2AScanner
from medusa.scanners.prompt_leakage_scanner import PromptLeakageScanner
from medusa.scanners.tool_callback_scanner import ToolCallbackScanner
from medusa.scanners.agent_reflection_scanner import AgentReflectionScanner
from medusa.scanners.agent_planning_scanner import AgentPlanningScanner
from medusa.scanners.multi_agent_scanner import MultiAgentScanner
from medusa.scanners.owasp_llm_scanner import OWASPLLMScanner
from medusa.scanners.model_attack_scanner import ModelAttackScanner
from medusa.scanners.llmops_scanner import LLMOpsScanner
from medusa.scanners.vector_db_scanner import VectorDBScanner
from medusa.scanners.modelscan_scanner import ModelScanScanner
from medusa.scanners.garak_scanner import GarakScanner
from medusa.scanners.llm_guard_scanner import LLMGuardScanner
from medusa.scanners.critical_cve_scanner import CriticalCVEScanner
from medusa.scanners.mcp_remote_rce_scanner import MCPRemoteRCEScanner
from medusa.scanners.docker_mcp_scanner import DockerMCPScanner
from medusa.scanners.post_quantum_scanner import PostQuantumScanner
from medusa.scanners.steganography_scanner import SteganographyScanner
from medusa.scanners.hyperparameter_scanner import HyperparameterScanner
from medusa.scanners.plugin_security_scanner import PluginSecurityScanner
from medusa.scanners.excessive_agency_scanner import ExcessiveAgencyScanner
from medusa.scanners.prompt_injection_code_scanner import PromptInjectionCodeScanner
from medusa.scanners.dataset_injection_scanner import DatasetInjectionScanner
from medusa.scanners.claude_code_scanner import ClaudeCodeScanner
from medusa.scanners.ai_attack_signature_scanner import AIAttackSignatureScanner
from medusa.scanners.web_security_scanner import WebSecurityScanner
from medusa.scanners.gitleaks_scanner import GitLeaksScanner
from medusa.scanners.semgrep_scanner import SemgrepScanner
from medusa.scanners.trivy_scanner import TrivyScanner
from medusa.scanners.ucp_scanner import UCPScanner
from medusa.scanners.ap2_scanner import AP2Scanner
from medusa.scanners.pi_scan_code_scanner import PISCANCodeScanner
from medusa.scanners.ast_behavior_scanner import AstBehaviorScanner
from medusa.scanners.dependency_cve_scanner import DependencyCVEScanner
from medusa.scanners.skill_manifest_scanner import SkillManifestScanner
from medusa.scanners.taint_scanner import TaintScanner
from medusa.scanners.llm_provider_hijack_scanner import LLMProviderHijackScanner
from medusa.scanners.image_embedded_threat_scanner import ImageEmbeddedThreatScanner
from medusa.scanners.credential_file_scanner import CredentialFileScanner
from medusa.scanners.remote_fetch_exec_scanner import RemoteFetchExecScanner
from medusa.scanners.yaml_rule_scanner import YAMLRuleScanner

# Create global scanner registry
registry = ScannerRegistry()

# Register all available scanners
registry.register(PythonScanner())
registry.register(BashScanner())
registry.register(BatScanner())
registry.register(DockerScanner())
registry.register(DockerComposeScanner())
registry.register(MarkdownScanner())
registry.register(JavaScriptScanner())
registry.register(TerraformScanner())
registry.register(GoScanner())
registry.register(JSONScanner())
registry.register(RubyScanner())
registry.register(PHPScanner())
registry.register(RustScanner())
registry.register(SQLScanner())
registry.register(CSSScanner())
registry.register(HTMLScanner())
registry.register(KotlinScanner())
registry.register(SwiftScanner())
registry.register(CppScanner())
registry.register(JavaScanner())
registry.register(TypeScriptScanner())
registry.register(ScalaScanner())
registry.register(PerlScanner())
registry.register(PowerShellScanner())
registry.register(RScanner())
registry.register(AnsibleScanner())
registry.register(KubernetesScanner())
registry.register(TOMLScanner())
registry.register(XMLScanner())
registry.register(ProtobufScanner())
registry.register(GraphQLScanner())
registry.register(SolidityScanner())
registry.register(LuaScanner())
registry.register(ElixirScanner())
registry.register(HaskellScanner())
registry.register(ClojureScanner())
registry.register(DartScanner())
registry.register(GroovyScanner())
registry.register(VimScanner())
registry.register(CMakeScanner())
registry.register(MakeScanner())
registry.register(NginxScanner())
registry.register(ZigScanner())
registry.register(EnvScanner())
registry.register(MCPConfigScanner())
registry.register(MCPServerScanner())
registry.register(AIContextScanner())
registry.register(AgentMemoryScanner())
registry.register(RAGSecurityScanner())
registry.register(A2AScanner())
registry.register(PromptLeakageScanner())
registry.register(ToolCallbackScanner())
registry.register(AgentReflectionScanner())
registry.register(AgentPlanningScanner())
registry.register(MultiAgentScanner())
registry.register(OWASPLLMScanner())
registry.register(AIAttackSignatureScanner())
registry.register(ModelAttackScanner())
registry.register(LLMOpsScanner())
registry.register(VectorDBScanner())
registry.register(ModelScanScanner())
registry.register(GarakScanner())
registry.register(LLMGuardScanner())
registry.register(CriticalCVEScanner())
registry.register(MCPRemoteRCEScanner())
registry.register(DockerMCPScanner())
registry.register(PostQuantumScanner())
registry.register(SteganographyScanner())
registry.register(HyperparameterScanner())
registry.register(PluginSecurityScanner())
registry.register(ExcessiveAgencyScanner())
registry.register(PromptInjectionCodeScanner())
registry.register(DatasetInjectionScanner())
registry.register(ClaudeCodeScanner())
registry.register(WebSecurityScanner())
registry.register(GitLeaksScanner())
registry.register(SemgrepScanner())
registry.register(TrivyScanner())
registry.register(UCPScanner())
registry.register(AP2Scanner())
registry.register(PISCANCodeScanner())
registry.register(AstBehaviorScanner())
registry.register(DependencyCVEScanner())
registry.register(SkillManifestScanner())
registry.register(TaintScanner())
registry.register(LLMProviderHijackScanner())
registry.register(ImageEmbeddedThreatScanner())
registry.register(CredentialFileScanner())
registry.register(RemoteFetchExecScanner())
# YAMLRuleScanner is available but NOT registered by design — every rule
# should be claimed by a specific scanner with proper file/context gating.
# Orphaned rules indicate a wiring gap that should be fixed at the rule or
# scanner level, not papered over with a catch-all.
# registry.register(YAMLRuleScanner())

__all__ = [
    'BaseScanner',
    'ScannerRegistry',
    'ScannerResult',
    'ScannerIssue',
    'Severity',
    'PythonScanner',
    'BashScanner',
    'BatScanner',
    'DockerScanner',
    'DockerComposeScanner',
    'MarkdownScanner',
    'JavaScriptScanner',
    'TerraformScanner',
    'GoScanner',
    'JSONScanner',
    'RubyScanner',
    'PHPScanner',
    'RustScanner',
    'SQLScanner',
    'CSSScanner',
    'HTMLScanner',
    'KotlinScanner',
    'SwiftScanner',
    'CppScanner',
    'JavaScanner',
    'TypeScriptScanner',
    'ScalaScanner',
    'PerlScanner',
    'PowerShellScanner',
    'RScanner',
    'AnsibleScanner',
    'KubernetesScanner',
    'TOMLScanner',
    'XMLScanner',
    'ProtobufScanner',
    'GraphQLScanner',
    'SolidityScanner',
    'LuaScanner',
    'ElixirScanner',
    'HaskellScanner',
    'ClojureScanner',
    'DartScanner',
    'GroovyScanner',
    'VimScanner',
    'CMakeScanner',
    'MakeScanner',
    'NginxScanner',
    'ZigScanner',
    'EnvScanner',
    'MCPConfigScanner',
    'MCPServerScanner',
    'AIContextScanner',
    'AgentMemoryScanner',
    'RAGSecurityScanner',
    'A2AScanner',
    'PromptLeakageScanner',
    'ToolCallbackScanner',
    'AgentReflectionScanner',
    'AgentPlanningScanner',
    'MultiAgentScanner',
    'OWASPLLMScanner',
    'AIAttackSignatureScanner',
    'ModelAttackScanner',
    'LLMOpsScanner',
    'VectorDBScanner',
    'ModelScanScanner',
    'GarakScanner',
    'LLMGuardScanner',
    'CriticalCVEScanner',
    'MCPRemoteRCEScanner',
    'DockerMCPScanner',
    'PostQuantumScanner',
    'SteganographyScanner',
    'HyperparameterScanner',
    'PluginSecurityScanner',
    'ExcessiveAgencyScanner',
    'PromptInjectionCodeScanner',
    'DatasetInjectionScanner',
    'ClaudeCodeScanner',
    'AstBehaviorScanner',
    'DependencyCVEScanner',
    'SkillManifestScanner',
    'TaintScanner',
    'WebSecurityScanner',
    'GitLeaksScanner',
    'SemgrepScanner',
    'TrivyScanner',
    'LLMProviderHijackScanner',
    'ImageEmbeddedThreatScanner',
    'CredentialFileScanner',
    'RemoteFetchExecScanner',
    'YAMLRuleScanner',
    'registry',
]
