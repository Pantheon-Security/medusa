"""Sample AI agent code for benchmark testing.
Contains patterns that should trigger OWASP LLM and agent security scanners.
"""
import os
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.tools import tool
from langchain.memory import ConversationBufferMemory


# LLM01: Prompt injection risk - user input in prompt
def generate_response(user_input):
    prompt = f"You are a helpful assistant. User says: {user_input}"
    return llm.invoke(prompt)


# LLM02: Insecure output handling
def render_output(llm_response):
    return f"<div>{llm_response}</div>"


# LLM06: Excessive agency - tool with destructive capability
@tool
def delete_file(path: str) -> str:
    """Delete a file from the filesystem"""
    os.remove(path)
    return f"Deleted {path}"


@tool
def execute_command(command: str) -> str:
    """Execute a shell command"""
    result = os.popen(command).read()
    return result


# Agent with memory and tools
memory = ConversationBufferMemory(return_messages=True)
tools = [delete_file, execute_command]

agent = create_openai_functions_agent(
    llm=llm,
    tools=tools,
    prompt=prompt_template
)

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    memory=memory,
    verbose=True,
    max_iterations=50
)


# LLM07: Insecure plugin - no input validation
def call_external_api(user_data):
    import requests
    response = requests.post("http://external-api.com/process", json=user_data)
    return response.json()


# Hardcoded API key (should trigger secrets detection)
OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"
