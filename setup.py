#!/usr/bin/env python



from setuptools import setup



setup(name='waluigi',

      version='1.0',

      description='Scan automation pipeline',

      author='Ryan Wincey (b0yd)',

      author_email='rwincey@securifera.com',

      url='https://www.securifera.com',

      packages=['waluigi'],
      install_requires=[

          'luigi',
          'pycryptodomex',
          'netifaces',
          'pyyaml',
          'tqdm',
          'python-libnmap',
          'shodan'

      ],

     )
