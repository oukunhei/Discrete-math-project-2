# Discrete-math-project-2

## Task Description
- Implement the RSA algorithm with the key generation, encryption, and decryption functions.
- Implement the ElGamal algorithm with the key generation, encryption, and decryption functions.
- Test the implementation with the encryption/decryption of short and long “textual” messages.
- Analyze the performance and security level of RSA and ElGamal.

## About the Project

### File Structure

Discrete-math-project-2\
├── README.md # 安装与运行说明\
├── RSA/\
│ ├── RSA_1.py # \ Basic
│ ├── RSA_2.py # \ PKCS#1 v1.5 padding
│ ├── RSA_3.py # \ +AES
│ ├── RSA_4.py # \ add OAEP padding and PKCS#1 v1.5 padding
│ ├── RSA_textual.py # \
│ ├── RSA_textual1.py \
│ ├── RSA_textual2.py \
│ └── test.py # \
├── ElGamal/\
│ ├── ElGamal_1.py # Basic ElGamal\
│ ├── ElGamal_2.py # Optimized Encrypting Efficiency\
│ ├── ElGamal_3.py # Improved Security Level\
│ ├── ElGamal_textual1.py # Test Running Time of the Algorithm\
│ ├── test_1.py # test the basic ElGamal_1.py \
│ └── test_3.py # test the ElGamal_3.py file\
│ └── textual2.py # test the algorithm correctness\
├── security/\ 
│ ├── security_ELG.py \
│ ├── security_RSA1.py \
│ ├── security_RSA2.py \
│ ├── security_RSA3.py \
│ └── security_RSA4.py \
├── Performance.ipynb # 

## Getting Started

### Prerequisites
Python 3.7 or higher is required.

Check your Python version with:
```bash
python --version  # or python3 --version
```
If needed, download Python from python.org.

## Dependencies
The following Python libraries are required (install via `pip`):

```bash
pip install cryptography
```

### Verifying Installation
Run the following command to check if dependencies are installed successfully:
```bash
python -c "import cryptography; print('cryptography loaded successfully!')"
```
If no errors occur, the environment setup is complete.

## RSA Algorithm

This RSA algorithm includes utilities for generating prime numbers, RSA key pairs, and performing cryptographic operations.

### Core files
- `RSA_1.py`: Contains the main RSA class with basic methods for generating keys, encrypting, and decrypting messages.
- `RSA_2.py`: Implement PKCS#1 v1.5to prevent padding oracle attack
- `RSA_3.py`: The hybrid encryption implementation of RSA encryption algorithm and AES symmetric encryption algorithm
- `RSA_4.py`: Adopt cryptography package to add OAEP padding and PKCS#1 v1.5 padding
- `RSA_textual2.py`: Test correctness and running time for textual messages of the algorithm simply

### Usage
```bash
python RSA_1.py
```
all can directly run, but evaluation need to be improved

## ElGamal Algorithm

This ElGamal algorithm implements an asymmetric encryption system using large prime numbers and modular exponentiation for secure key exchange and message encryption/decryption.

### Core files
- `ElGamal_1.py`: Basic realization of the ElGamal Algorithm
- `ElGamal_2.py`: Improved the efficiency of finding a generator
- `ElGamal_3.py`: Improved Security Level
- `ElGamal_textual1.py`: Test correctness and running time for textual messages of the algorithm simply
- `test_1.py`: test the basic ElGamal_1.py 
- `test_3.py`: test the ElGamal_3.py file
- `textual2.py`: test the algorithm correctness for textual messages

### Usage
```bash
python test.py
```

## Analysis

### Core files
- `security_ELG.py`: Test the security.
- `security_RSA1.py`: Test the security.
- `security_RSA2.py`: Test the security.
- `security_RSA3.py`: Test the security.
- `security_RSA4.py`: Test the security.

### Core files
- `Performance.ipynb`: Quantified performance test and visualization.

