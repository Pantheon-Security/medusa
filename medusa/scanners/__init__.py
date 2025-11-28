"""
MEDUSA Scanner Heads
54 independent security scanner implementations
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
from medusa.scanners.yaml_scanner import YAMLScanner
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

# Create global scanner registry
registry = ScannerRegistry()

# Register all available scanners
registry.register(PythonScanner())
registry.register(BashScanner())
registry.register(BatScanner())
registry.register(YAMLScanner())
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

__all__ = [
    'BaseScanner',
    'ScannerRegistry',
    'ScannerResult',
    'ScannerIssue',
    'Severity',
    'PythonScanner',
    'BashScanner',
    'BatScanner',
    'YAMLScanner',
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
    'registry',
]
