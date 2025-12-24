"""
Security Chatbot Agent Module
Exposes the agent for ADK web UI

This file is required for ADK web to discover and load your agent.
"""

from .agent import root_agent

__all__ = ['root_agent']