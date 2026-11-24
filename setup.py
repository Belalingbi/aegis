from setuptools import setup, find_packages

setup(
    name="aegis-sec",
    version="0.2.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.1.0",
        "rich>=13.7.0",
        "requests>=2.31.0",
        "psutil>=5.9.0",
        "textual>=0.40.0",
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "aegis=aegis.cli:main",
            "aegis-sec=aegis.cli:main",
        ],
    },
)
