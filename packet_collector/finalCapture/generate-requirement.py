import pkg_resources

# List the imported modules from your script
packages = ['requests', 'argparse', 'pandas', 'pickle', 'numpy', 'os']

# Loop through the packages and print their version
with open("requirements.txt", "w") as f:
    for package in packages:
        try:
            version = pkg_resources.get_distribution(package).version
            f.write(f"{package}=={version}\n")
            print(f"{package}=={version}")
        except pkg_resources.DistributionNotFound:
            print(f"{package} is not installed")
