from setuptools import setup, find_packages

setup(
    name="phish-detect",
    version="1.0.0",
    description="Phishing Email Detection Tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/phish-detect",
    packages=find_packages(),
    install_requires=[
        "beautifulsoup4>=4.13.5",
        "openpyxl>=3.1.5",
        "pandas>=2.3.2",
        "psycopg2-binary>=2.9.10",
        "python-dotenv>=1.0.0",
        "streamlit>=1.49.1",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
