from setuptools import setup

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="pyoti",
    version="0.1",
    description="Python API for Threat Intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RH-ISAC/PyOTI",
    author="goodlandsecurity",
    author_email="jj.josing@rhisac.org",
    license="GNU GPLv3",
    packages=["pyoti"],
    zip_safe=False,
)
