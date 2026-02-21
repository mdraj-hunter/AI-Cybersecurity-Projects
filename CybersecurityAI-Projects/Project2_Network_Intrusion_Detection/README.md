# Network Intrusion Detection System

A machine learning-based system for detecting network intrusions and attacks in real-time.

## Overview

This project implements a Network Intrusion Detection System (NIDS) that uses machine learning algorithms to identify various types of network attacks including:

- **DoS (Denial of Service)** - Flood attacks that overwhelm target systems
- **Probe Attacks** - Reconnaissance and scanning attacks
- **R2L (Remote to Local)** - Unauthorized access from remote machines
- **U2R (User to Root)** - Privilege escalation attacks

## Features

- Real-time packet capture and analysis
- Flow-based feature extraction
- Hybrid detection (signature + anomaly-based)
- Multiple attack type classification
- Severity assessment
- Model persistence and loading

## Installation

```bash
# Install dependencies
pip install numpy pandas scikit-learn

# Or install from requirements
pip install