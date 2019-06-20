from setuptools import setup, find_packages

def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='dome9ApiV2Py',
      description='Dome9 api module',
      version="0.0.1",
      long_description=readme(),
      author='Dome9 api module',
      author_email='d9ops@checkpoint.com',
      license='MIT',
      packages=find_packages(),
      include_package_data=True,
      install_requires=[
                        'requests'
                        ],
      zip_safe=False)
