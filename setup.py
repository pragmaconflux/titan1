from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="titan-decoder",
    version="2.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced payload decoding and analysis engine for cybersecurity",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/titan-decoder",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "titan-decoder=titan_decoder.cli:main",
        ],
    },
    install_requires=[
        # Add dependencies here
    ],
    extras_require={
        "dev": ["pytest", "black", "flake8", "mypy"],
    },
)