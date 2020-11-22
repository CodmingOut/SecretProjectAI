#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 23 00:25:55 2020

@author: cpprhtn
"""


from zipfile import ZipFile
from os import listdir
from os.path import isfile, join

curdir = '/Users/cpprhtn/Desktop/data_zip'

onlyfiles = [join(curdir, f) for f in listdir(curdir) if isfile(join(curdir, f))]

for fileName in onlyfiles:
    if fileName[-3:] != 'zip':
        continue
    print(fileName)
    with ZipFile(fileName, 'r') as zf:
        print(fileName[:-4])
        zf.extractall(path = fileName[:-4], pwd=b"infected")
        zf.close()