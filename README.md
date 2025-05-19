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
│ ├── RSA_1.py # \
│ ├── RSA_2.py # \
│ ├── RSA_3.py # \
│ ├── RSA_4.py # \
│ ├── RSA_eval.py # \
│ ├── RSA_eval1.py # \
│ ├── RSA_textual.py # \
│ └── test.py # \
├── ElGamal/\
│ ├── ElGamal.py # basic ElGamal\
│ ├── ElGamal2.py # improved ElGamal of faster encrypting\
│ └── test.py # to be modified\


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
- `RSA_eval.py`: Test example - to be modified
- `RSA_eval1.py`: Test example - to be modified
- `RSA_textual.py`: Test example - to be modified

### Usage
```bash
python RSA_1.py
```
all can directly run, but evaluation need to be improved

## ElGamal Algorithm

This ElGamal algorithm implements an asymmetric encryption system using large prime numbers and modular exponentiation for secure key exchange and message encryption/decryption.

### Core files
- `ElGamal.py`: Basic realization of the ElGamal Algorithm
- `ElGamal.py2`: Improved the efficiency of finding a generator
- `test.py`: test the algorithm

### Usage
```bash
python test.py
```

