import typer
from enum import Enum
import sys
from loguru import logger
from lightrag import LightRAG, QueryParam
from lightrag.llm import ollama_model_complete, ollama_embedding # import the function to use the LLM model
from lightrag.utils import EmbeddingFunc
from pymongo.errors import ConnectionFailure, ConfigurationError
from pymongo import MongoClient
from models import CVEDescription,RAGModel
from tqdm import tqdm

logger.remove()  # 移除默认的日志
logger.add(sys.stdout,
    format="{time:MM-dd HH-mm-ss} [{level}] {function} {message}",
    level="INFO"
)
class TargetDB(str, Enum):
    """Enum for the target database options."""
    cvefix = "cvefix"
    vulnsrc = "vulnsrc"


class LLMBackend(str, Enum):
    """Enum for the LLM backend types."""
    ollama = "ollama"
    openai = "openai"
    azure_openai = "azure-openai"
    deepseek = "deepseek"

def main(
    mongo_host: str = typer.Option("localhost", help="MongoDB host address"),
    mongo_port: int = typer.Option(27017, help="MongoDB port"),
    target_db: TargetDB = typer.Option(..., help="Target database name", case_sensitive=False),
    llm_type: LLMBackend = typer.Option(..., help="LLM backend type", case_sensitive=False),
    llm_model: str = typer.Option(..., help="Name of the LLM model"),
    embed_model: str = typer.Option(..., help="Embedding model name"),
    llm_host: str = typer.Option("http://localhost:11434", help="LLM host address"),
    rec_cnt:int=typer.Option(default=10, help="How many records will be parsed to LightRAG"),
):
    """
    Command-line interface for configuring a MongoDB and LLM-related deployment.
    """
    mongo_uri = f"mongodb://{mongo_host}:{mongo_port}"

    if llm_type != LLMBackend.ollama:
        raise NotImplementedError(f"LLM backend {llm_type} not implemented yet.")
    rag=LightRAG(
        working_dir=f"./{target_db.value}",
        llm_model_func=ollama_model_complete, # NOTE: only support ollama yet
        llm_model_name=llm_model,
        llm_model_kwargs={"host": llm_host, "options": {"num_ctx": 32768}},
        embedding_func=EmbeddingFunc(
            embedding_dim=1024,  # NOTE: Must match the embedding dimension of the model!
            max_token_size=8192,
            func=lambda texts: ollama_embedding(
                texts, embed_model=embed_model, host=llm_host
            ),
        ),

    )
    logger.info(f"Initialized LightRAG")

    # Connect mongo
    try:
        client = MongoClient(mongo_uri)
        db = client[target_db.value]
        collection = db['cve'] if target_db == TargetDB.cvefix else db['cves']
    except ConnectionFailure as e:
        typer.echo(f"Failed to connect to MongoDB: {e}")
        collection = None
    except ConfigurationError as e:
        typer.echo(f"Configuration error in MongoDB connection: {e}")
        collection = None
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}")
        collection = None
    with collection.find({}) as cursor:  
        cnt=rec_cnt
        for document in tqdm(cursor,desc="Processing Records",):
            model= CVEDescription.model_validate({**document}) 
            #logger.info (f"Getting document {model.cve_meta.cve_number} with {str(model)}")
            insert_ready_model=RAGModel(cve_number=model.cve_meta.cve_number,title=model.cve_meta.title,desc=model.desc)
            #logger.info(f"CVE number: {model.cve_meta.cve_number} will insert the description {str(insert_ready_model)}")
            rag.insert(str(insert_ready_model))
            cnt-=1
            if cnt==0:
                break

if __name__ == "__main__":
    typer.run(main)