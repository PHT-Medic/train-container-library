import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pht-train-container-library",
    version="0.0.1",
    author="Michael Graf",
    author_email="",
    description="PHT train container library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/PersonalHealthTrain/implementations/germanmii/difuture/train-container-library.git",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)