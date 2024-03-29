from setuptools import setup

from snap4n6 import __version__

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name = "snap4n6",
    version = __version__,
    description = "Rebuild Elastic Block Storage (EBS) direct API blocks into a DD forensic image generated by Snap4n6 Serverless Imager.",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/4n6ir/snap4n6cli",
    author = "John Lukach",
    author_email = "hello@lukach.io",
    license = "Apache-2.0",
    packages = ["snap4n6"],
    install_requires = ["boto3","tqdm"],
    zip_safe = False,
    entry_points = {
        "console_scripts": ["snap4n6=snap4n6.cli:main"],
    },
    python_requires = ">=3.7",
)
