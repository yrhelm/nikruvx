"""PHI lineage ingesters.

Five sources, all producing the normalized engine.phi_lineage.CallEvent:
    sdk_shim.py            - monkey-patch openai/anthropic Python SDKs
    openai_proxy.py        - HTTP proxy (uvicorn-deployable) for /v1
    bedrock_cloudtrail.py  - AWS CloudTrail JSON parser
    azure_openai.py        - Azure Monitor diagnostic-log parser
    mcp_inspector.py       - inspect installed MCP servers for PHI signals
"""
