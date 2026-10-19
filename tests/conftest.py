"""
tests/conftest.py
Root conftest: ensure the gateway package is importable in tests.
"""
import sys
import os

# Add the bayora repo root to sys.path so "gateway.app" resolves correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
