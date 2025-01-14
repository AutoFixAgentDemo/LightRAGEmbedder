import os
import logging
from lightrag import LightRAG, QueryParam
from lightrag.llm import ollama_model_complete, ollama_embedding # import the function to use the LLM model
from lightrag.utils import EmbeddingFunc
WORKING_DIR = "./dickens"
logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)
if not os.path.exists(WORKING_DIR):
    os.mkdir(WORKING_DIR)

rag = LightRAG(
    working_dir=WORKING_DIR,
    llm_model_func=ollama_model_complete,
    llm_model_name="qwen2.5:32b",
    llm_model_max_async=4,
    llm_model_max_token_size=32768,
    llm_model_kwargs={"host": "http://172.17.0.16:11434", "options": {"num_ctx": 32768}},
    embedding_func=EmbeddingFunc(
        embedding_dim=1024, # NOTE:Must match the embedding dimension of the model!
        max_token_size=8192,
        func=lambda texts: ollama_embedding(
            texts, embed_model="mxbai-embed-large:latest", host="http://172.17.0.16:11434"
        ),
    ),
)

with open("./book.txt", "r", encoding="utf-8") as f:
    rag.insert(f.read())

# Perform naive search
print(rag.query("What are the top themes in this story?", param=QueryParam(mode="naive")))
# Perform local search
print(rag.query("What are the top themes in this story?", param=QueryParam(mode="local")))
# Perform global search
print(rag.query("What are the top themes in this story?", param=QueryParam(mode="global")))
# Perform hybrid search
print(rag.query("What are the top themes in this story?", param=QueryParam(mode="hybrid")))
