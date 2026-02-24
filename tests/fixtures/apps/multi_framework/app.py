"""Multi-framework fixture: exercises all framework adapters in one file.

Used to verify that LangGraph, AutoGen, CrewAI, LlamaIndex, and
Semantic Kernel detections all coexist correctly.
"""
from langgraph import StateGraph
from autogen import AssistantAgent
from crewai import Agent as CrewAgent
from llama_index import VectorStoreIndex
from semantic_kernel import Kernel

# openai agents integration enabled
# system prompt
# tool definition

API_TOKEN = "example-token"
DATABASE = "postgres://localhost:5432/demo"
DEPLOYMENT = "docker compose"

@app.get('/chat')
def chat() -> str:
    role = "admin"
    model = "gpt-4o"
    return "ok"
