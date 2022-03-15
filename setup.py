from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

# with open("requirements.txt", "r") as rf:
#     requirements = rf.readlines()
#
# with open("requirements_dev.txt", "r") as rfd:
#     dev_requirements = rfd.readlines()

setup(
    name="pht-train-container-library",
    version="1.1.0",
    author="Michael Graf",
    author_email="michael.graf@uni-tuebingen.de",
    description="PHT train container library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PHT-Medic/train-container-library",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords=["PHT", "security", "encryption", "personalhealthtrain", "docker"],
    python_requires=">=3.7",
    install_requires=[
        "cryptography",
        "pandas",
        "requests",
        "python-dotenv",
        "hvac",
        "fhir-kindling",
        "loguru",
        "pendulum",
        "pika",
        "xmltodict",
        "oauthlib",
        "requests_oauthlib",
        "docker",
        "loguru",
    ],
)
