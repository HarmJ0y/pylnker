from setuptools import setup
setup(
    name='pylnker',
    version='1.0.0',
    description='Python port of lnk-parse-1.0, a tool to parse Windows .lnk files',
    long_description='Python port of lnk-parse-1.0, a tool to parse Windows .lnk files',
    url='https://github.com/HarmJ0y/pylnker',
    author='HarmJ0y',
    license='GPL2',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='lnk parser',
    scripts=['pylnker.py'],
)
