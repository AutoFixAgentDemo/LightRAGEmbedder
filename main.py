import typer
from enum import Enum
import sys
from loguru import logger
from lightrag import LightRAG, QueryParam
from lightrag.llm.ollama import ollama_model_complete, ollama_embed # import the function to use the LLM model
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
def convert_model_to_string(model: CVEDescription) -> str:
    """
    Convert a BaseModel object to a string for insertion into the LightRAG.
    """
    return f"""
    {model.cve_meta.cve_number} is a vulnerability with title {model.cve_meta.title}. There are several functions related to this vulnerability:
    {chr(10).join([f"{func.function_name}: {func.general_purpose}" for func in model.desc.funcs_desc.functional_desc])}
    {model.cve_meta.cve_number} is related to the following CWEs:{model.cve_meta.weaknesses}
    {model.cve_meta.cve_number} is caused by the following flaws:{model.desc.sec_desc.description}: {model.desc.sec_desc.vulnerability_cause_details}
    {model.cve_meta.cve_number} is fixed by deploying the following patch methods:{model.desc.sec_desc.patch_details}
    """
    # chr(10) is the \n to bypass the SyntaxError: f-string expression part cannot include a backslash
def main(
    mongo_host: str = typer.Option("localhost", help="MongoDB host address"),
    mongo_port: int = typer.Option(27017, help="MongoDB port"),
    target_db: TargetDB = typer.Option(..., help="Target database name", case_sensitive=False),
    llm_type: LLMBackend = typer.Option(..., help="LLM backend type", case_sensitive=False),
    llm_model: str = typer.Option(..., help="Name of the LLM model"),
    embed_model: str = typer.Option(..., help="Embedding model name"),
    llm_host: str = typer.Option("http://localhost:11434", help="LLM host address"),
    rec_cnt:int=typer.Option(default=-1, help="How many records will be parsed to LightRAG. -1 for no limit"),
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
            func=lambda texts: ollama_embed(
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
        if rec_cnt == -1:
            # 不限制的情况下，使用 tqdm 不设置 total
            with tqdm(cursor, desc="Processing Records (Unlimited)") as progress_bar:
                for document in progress_bar:
                    model = CVEDescription.model_validate({**document})
                    rag.insert(convert_model_to_string(model))
        else:
            # 限制记录数时，设置 tqdm 的 total
            remaining_count = rec_cnt
            with tqdm(cursor, desc="Processing Records", total=rec_cnt) as progress_bar:
                for document in progress_bar:
                    model = CVEDescription.model_validate({**document})
                    ins_str=convert_model_to_string(model)
                    logger.debug(f"Processing {model.cve_meta.cve_number} with the following string:{ins_str}")
                    rag.insert(ins_str)
                    remaining_count -= 1
                    if remaining_count == 0:
                        break

if __name__ == "__main__":
    typer.run(main)