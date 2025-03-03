# LightRAGEmbedder
Vectorize and embed semantic CVE data into LightRAG. Only support Ollama-based LLM for now.

## Prerequisites

A database of semantic information extracted from the `Vulnsrc` and `CVEFIX` datasets must be prepared. They should be saved in mongo with the following db name:
- `CVEFIX`:`cvefix`
- `VulnSrc`:`vulnsrc`

## Install

Prepare for the conda env

```shell
conda env create -f environment.yaml
```

Install LightRAG

```shell
conda activate lightrag-embedder
git clone https://github.com/HKUDS/LightRAG.git
cd lightrag
pip install -e "."
```

## Usage

```shell
python3 main.py --help
```

Example:
```shell
python3 main.py --mongo-host=<MONGO_HOST> --mongo-port=<MONGO_PORT> --target-db=vulnsrc --llm-model=qwen2.5:32b  --embed-model mxbai-embed-large:latest --llm-type=ollama --llm-host=<LLM_HOST>
```
```shell
python3 main.py  --target-db=vulnsrc --llm-model=qwen2.5:32b  --embed-model mxbai-embed-large:latest --llm-type=ollama --llm-host=http://172.17.0.16:11434 --mongo-host=172.17.0.15 --rec-cnt=10
```