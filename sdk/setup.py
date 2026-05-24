from setuptools import setup, find_packages
setup(
    name="vault-zero-sdk",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "websockets>=12.0",
        "msgpack>=1.0",
        "cryptography>=42.0",
    ],
    python_requires=">=3.10",
    description="Official Python SDK for Vault-Zero",
    author="Master Prem",
    url="https://github.com/yourusername/vault-zero",
)
