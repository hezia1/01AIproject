FROM mcr.microsoft.com/playwright/python:v1.54.0-noble

RUN pip install --no-cache-dir playwright==1.54.0

LABEL ai-security-platform.sandbox-browser-executor="true"
