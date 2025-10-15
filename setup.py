from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aje-cdk-libs",
    version="0.1.0",  # Usa versionado semántico
    author="Miguel Espinoza Alvarez",
    author_email="mespinoza1388@gmail.com",
    description="Librería de utilidades para CDK con un standard de codificación para los proyectos de AWS en Ajegroup",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MR34Z1r0/aje-cdk-libs",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        # Lista tus dependencias aquí, por ejemplo:
        "aws-cdk-lib==2.99.0",
        "aws-cdk.aws-glue-alpha==2.54.0a0",
        "python-dotenv"
    ],
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)