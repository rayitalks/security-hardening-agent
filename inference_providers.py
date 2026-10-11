"""Named text-chat serving profiles; no runtime installation or auto-detection.

Defaults are editable examples. Compatibility is established by calls to the
selected deployment, never by the name of its profile. Reviewed 2026-10-04.
"""
from urllib.parse import urlsplit


def _profile(identity, name, port, notes, docs, protocol='openai'):
    return dict(id=identity, name=name, protocol=protocol,
                defaultUrl=f'http://127.0.0.1:{port}' + ('' if protocol == 'ollama' else '/v1'),
                notes=notes, docs=docs)


PROFILES = [
    _profile('ollama', 'Ollama', 11434,
             'Uses native /api/tags and /api/chat. Choose a chat-capable model; reasoning is disabled for bounded tests.',
             'https://docs.ollama.com/api/chat', 'ollama'),
    _profile('vllm', 'vLLM', 8000,
             'Uses the served model name or LoRA alias returned by /v1/models. Chat requires a suitable chat template. GPU, CPU and distributed deployments use the same HTTP API.',
             'https://docs.vllm.ai/en/latest/serving/online_serving/'),
    _profile('sglang', 'SGLang', 30000,
             'Select the OpenAI-compatible server frontend and a chat model. Native /generate is outside this adapter.',
             'https://docs.sglang.io/docs/basic_usage/openai_api'),
    _profile('llamacpp', 'llama.cpp / llama-server', 8080,
             'Connect to llama-server with a chat template. Uses its OpenAI-compatible model list and chat API.',
             'https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md'),
    _profile('lmstudio', 'LM Studio', 1234,
             'Enable the local server. Discovery can include unloaded or embedding models; select a text-chat model.',
             'https://lmstudio.ai/docs/developer/openai-compat'),
    _profile('localai', 'LocalAI', 8080,
             'Choose a configured text-chat model. Image, audio and embedding models do not support these boundary tests.',
             'https://github.com/mudler/LocalAI'),
    _profile('tgi', 'Hugging Face TGI', 8080,
             'Requires the Messages API and a chat template (TGI 1.4+). Older inventories fall back to the read-only /info model_id.',
             'https://huggingface.co/docs/text-generation-inference/messages_api'),
    _profile('trtllm', 'NVIDIA TensorRT-LLM / trtllm-serve', 8000,
             'Use the trtllm-serve OpenAI-compatible HTTP frontend. Native engine files and raw tensor endpoints are not chat APIs.',
             'https://nvidia.github.io/TensorRT-LLM/commands/trtllm-serve.html'),
    _profile('triton', 'NVIDIA Triton — OpenAI frontend', 9000,
             'Requires Triton\'s separately configured OpenAI frontend (commonly port 9000). Native /v2 tensor inference and gRPC are not supported here.',
             'https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/client_guide/openai_readme.html'),
    _profile('nim', 'NVIDIA NIM', 8000,
             'Use a deployed NIM LLM service and its returned model ID. Other NIM modalities need separate validation.',
             'https://docs.nvidia.com/nim/large-language-models/latest/api-reference.html'),
    _profile('dynamo', 'NVIDIA Dynamo', 8000,
             'Connect to the OpenAI-compatible frontend for the selected deployment; worker and discovery ports are not inference URLs.',
             'https://github.com/ai-dynamo/dynamo'),
    _profile('lmdeploy', 'LMDeploy / TurboMind', 23333,
             'Connect to lmdeploy serve api_server and use its served model identity.',
             'https://lmdeploy.readthedocs.io/en/latest/llm/api_server.html'),
    _profile('xinference', 'Xinference', 9997,
             'Use the launched model UID returned by the OpenAI-compatible model inventory.',
             'https://inference.readthedocs.io/en/latest/user_guide/client_api.html'),
    _profile('aphrodite', 'Aphrodite / Sonar', 2242,
             'Use the OpenAI-compatible HTTP service and its configured port. The upstream Aphrodite project now redirects to Sonar.',
             'https://github.com/dphnAI/sonar'),
    _profile('tabbyapi', 'TabbyAPI / ExLlama', 5000,
             'Use the inference API key, not an admin key. Select the configured chat model.',
             'https://github.com/theroyallab/tabbyAPI'),
    _profile('mlx', 'MLX-LM server', 8080,
             'Use mlx_lm.server on the serving Mac. The server must expose /v1/models and chat completions; older builds may need updating.',
             'https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/server.py'),
    _profile('llamafile', 'llamafile', 8080,
             'Connect to the llama.cpp-compatible server mode with a chat model and template.',
             'https://github.com/mozilla-ai/llamafile'),
    _profile('koboldcpp', 'KoboldCpp', 5001,
             'Uses the OpenAI-compatible API. System-role behavior depends on the selected model and chat template.',
             'https://github.com/LostRuins/koboldcpp'),
    _profile('textgen', 'Text generation WebUI / textgen', 5000,
             'Enable its OpenAI API server. The web UI port is different from the inference API port.',
             'https://github.com/oobabooga/textgen/wiki/12-%E2%80%90-OpenAI-API'),
    _profile('rayserve', 'Ray Serve LLM', 8000,
             'Use a deployed OpenAI-compatible LLM application, not the Ray dashboard. Preserve any configured application path prefix.',
             'https://docs.vllm.ai/en/latest/serving/online_serving/#ray-serve-llm'),
    _profile('litellm', 'LiteLLM proxy', 4000,
             'Validates the selected proxy route and model alias. This does not identify or independently validate the underlying inference engine.',
             'https://docs.litellm.ai/docs/proxy/quick_start'),
    _profile('openai', 'Other OpenAI-compatible server', 8000,
             'Requires GET /v1/models and POST /v1/chat/completions with text messages. Set the exact base URL for your server or gateway.',
             'https://docs.vllm.ai/en/latest/serving/online_serving/'),
]
_BY_ID = {row['id']: row for row in PROFILES}


def profile(kind):
    if not isinstance(kind, str) or kind not in _BY_ID:
        raise ValueError('Choose a supported inference engine or Other OpenAI-compatible server.')
    return dict(_BY_ID[kind])


def catalog():
    return {'schema': 'sha-endpoint-providers-v1', 'reviewedAt': '2026-10-04',
            'providers': [dict(row) for row in PROFILES],
            'coverage': 'Text-chat HTTP adapters only. Profiles are selected by the user, not detected engine identities. Defaults are editable examples, not evidence of an installed engine.'}


def api_paths(kind, base):
    selected = profile(kind)
    path = urlsplit(base.rstrip('/')).path.rstrip('/')
    if path.endswith(('/chat/completions', '/models', '/api/chat', '/api/tags', '/generate', '/info')):
        raise ValueError('Enter the server base URL, not a model-list or inference request URL.')
    if selected['protocol'] == 'ollama':
        if path.endswith('/v1'):
            raise ValueError('For native Ollama, remove /v1 or select Other OpenAI-compatible server.')
        return ('/tags', '/chat') if path.endswith('/api') else ('/api/tags', '/api/chat')
    return ('/models', '/chat/completions') if path.endswith('/v1') else ('/v1/models', '/v1/chat/completions')
