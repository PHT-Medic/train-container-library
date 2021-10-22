import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as rf:
    requirements = rf.readlines()

with open("requirements_dev.txt", "r") as rfd:
    dev_requirements = rfd.readlines()

setuptools.setup(
    name="pht-train-container-library",
    version="0.9.0",
    author="Michael Graf",
    author_email="michael.graf@uni-tuebingen.de",
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
    keywords=['PHT', 'security', 'encryption', 'personalhealthtrain', 'docker'],
    python_requires='>=3.7',
    install_requires=requirements,
    tests_require=dev_requirements

)
