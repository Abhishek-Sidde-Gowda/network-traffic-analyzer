from setuptools import setup, find_packages

setup(
    name="network-traffic-analyzer",
    version="1.0.0",
    description="ML-powered network traffic analyzer and intrusion detection system",
    author="Abhishek Jayanth",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.5",
        "dpkt>=1.9",
        "pandas>=2.0",
        "numpy>=1.24",
        "scikit-learn>=1.3",
        "joblib>=1.3",
        "flask>=3.1",
        "rich>=13.0",
        "click>=8.1",
        "reportlab>=4.0",
    ],
    entry_points={
        "console_scripts": [
            "nta=cli:cli",
        ],
    },
)
