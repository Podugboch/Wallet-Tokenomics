---
name: crypto-wallet-tokenomics-forensics
description: An on-chain intelligence and tokenomics forensics skill that evaluates token contract addresses and wallet hashes, analyzing holder concentration, liquidity pools, and historical transaction anomalies.
version: 1.0.0
author: Patrick Sean Odugboche
license: MIT
metadata:
  category: Blockchain & Crypto Intelligence
  tags: [crypto, tokenomics, forensics, on-chain, wallet-analysis, ccxt]
---

# Crypto Tokenomics & On-Chain Wallet Forensics Analyzer

## Package Download (.zip)
* [Download crypto-wallet-tokenomics-forensics.zip](https://github.com/Podugboch/Wallet-Tokenomics/releases/download/v1.0.0/crypto-wallet-tokenomics-forensics.zip)
* [Download Repository .zip (main)](https://github.com/Podugboch/Wallet-Tokenomics/archive/refs/heads/main.zip)

> **Disclaimer:** *This skill is provided for educational, analytical, and research purposes only. It does not constitute financial or investment advice.*

This skill enables AI coding agents (such as Claude Code, Codex, and Cursor) to query public block explorer APIs, DEX liquidity endpoints, and multi-chain networks, performing on-chain forensics, holder concentration reviews, and anomaly detection.

## Quick Start & Usage

Ask your AI agent to run a wallet forensic audit:

```bash
python scripts/forensics.py --target 0x71C7656EC7ab88b098defB751B7401B5f6d8976F --type wallet
```

Run an on-chain tokenomics audit on a token contract address:
```bash
python scripts/forensics.py --target 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --type token
```

### Advanced Usage & Reporting Options

Generate a structured Markdown research dossier saved to disk:
```bash
python scripts/forensics.py \
  --target 0x71C7656EC7ab88b098defB751B7401B5f6d8976F \
  --type wallet \
  --format markdown \
  --output dossier_report.md
```

Export structured JSON data for programmatic analysis:
```bash
python scripts/forensics.py \
  --target 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --type token \
  --format json \
  --output metrics.json
```

Audit assets across alternative chains (e.g. Solana, Arbitrum, Base, BSC):
```bash
python scripts/forensics.py \
  --target EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
  --chain solana \
  --type token
```

### Supported Parameters
* `--target` (or `-t`): Wallet hash or token contract address to evaluate (required).
* `--type`: Target entity type (`wallet` or `token`, default: `wallet`).
* `--chain` (or `-c`): Target blockchain (`ethereum`, `bsc`, `polygon`, `arbitrum`, `base`, `solana`, default: `ethereum`).
* `--format` (or `-f`): Output report format (`text`, `markdown`, `json`, default: `text`).
* `--output` (or `-o`): Optional file path to export the research dossier.
* `--offline`: Force local deterministic analysis without external API calls.
* `--version` (or `-v`): Display current version number.

## Features Included
1. **Holder Concentration Analysis:** Inspects top distribution tiers (Top 10 / Top 50 share), computes Gini concentration coefficients, and flags whale dominance.
2. **Liquidity Pool Mapping:** Evaluates token pairings, liquidity depths across decentralized exchanges (Uniswap, SushiSwap, PancakeSwap, Raydium), and LP lock status.
3. **Historical Transaction Anomalies:** Flags high-velocity transfer clusters, wash-trading patterns, and liquidity drain signatures.
4. **Structured Research Dossier:** Generates clean Markdown reports and JSON feeds summarizing risk metrics and asset flows.

## Requirements & Scope
* **Environment:** Python 3.8+
* **Dependencies:** `requests>=2.31.0` (for live DEX pool metrics) and optional `rich>=13.0.0` (for terminal rendering). Includes resilient offline deterministic fallback.
