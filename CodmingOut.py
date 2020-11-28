# -*- coding: utf-8 -*-
"""
Created on Sat Nov 14 17:08:06 2020

@author: cpprh
"""


import numpy as np
import keras
import tensorflow as tf
import sys
import argparse
import re
import os
from sklearn.feature_extraction import FeatureHasher
from sklearn.model_selection import KFold
from keras.models import load_model
import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import SVG
from keras.utils.vis_utils import model_to_dot
from keras.utils import plot_model

# 외부에서 모델을 받아 올 수 있도록 제작
parser = argparse.ArgumentParser("멀웨어 탐색기 ")
parser.add_argument("--Malware_paths",default=None,help="Malware 데이터셋 경로 지정")
parser.add_argument("--Benignware_paths",default=None,help="Benignware 데이터셋 경로 지정")
parser.add_argument("--Scan_folder_path",default=None,help="스캔할 폴더 경로 지정")

hasher = FeatureHasher(20000)

#외부에서 경로를 입력받음


#args = parser.parse_args()

#모델 생성
args = parser.parse_args(['--Malware_paths', 'Master_malware', '--Benignware_paths', 'benignware'])

#파일 스캔
args = parser.parse_args(['--Scan_folder_path', 'test'])

#데이터셋에서 파일 가져옴
def get_dataset(benign_path,malicious_path,hasher):
    def getting_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
        return targets
    malicious_paths = getting_paths(malicious_path)
    benign_paths = getting_paths(benign_path)
    X = [get_str_features(path,hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
    return X, y

# TODO
    # get_str_features -> 바이너리 파일에서 문자열 전처리


# SW 바이너리의 문자열 특성을 파일 내 사용 가능한 문자의 연속 문자열 중 min_len을 넘는 길이의 문자열 사용
def get_str_features(path,hasher):
    # 정규 표현식을 이용하여 바이너리 파일에서 문자열 추출
    chars = r" -~"
    min_len = 5 #최소 길이
    str_RegExp = '[%s]{%d,}' % (chars, min_len) #최소 길이보다 큰 문자열만 추출
    file_object = open(path, encoding='iso-8859-1')
    data = file_object.read()
    pattern = re.compile(str_RegExp)
    strings = pattern.findall(data)
    
    
    # 추출된 문자열 길이 확인 -> 앞에서의 min_len보다 길이가 큰 str feature에 대한 카운트를 줌
    
    str_features = {}
    for string in strings:
        str_features[string] = 1
     
    
    #string 데이터타입을 dictionary로 변경
    hashing_features = hasher.transform([str_features])
    hashing_features = hashing_features.todense() #행렬로 반환
    hashing_features = np.asarray(hashing_features) #이후 np.ndarray()로 형변환
    hashing_features = hashing_features[0]
    
    
    # 해쉬 문자열 특성 반환
    print("{0} 경로에서 추출된 문자열 갯수 : {1}".format(path,len(str_features)))
    return hashing_features
    

#모델 학습 및 저장
def model_learning(X,y,hasher):
    X, y  = np.array(X), np.array(y)
    
    fold_ctr = 0
    fold = KFold(3,shuffle=True)
    for train, test in fold.split(X):
        training_X, training_y = X[train], y[train]
        test_X, test_y = X[test], y[test]
         
        training_X = training_X.reshape(-1, 1, 20000)
        training_y = training_y.reshape(-1, 1, )
        test_X = test_X.reshape(-1, 1, 20000)
        test_y = test_y.reshape(-1, 1, )
        
        model = keras.models.Sequential()
        model.add(keras.layers.Flatten(input_shape=(1, 20000)))
        model.add(keras.layers.Dropout(0.1))
        model.add(keras.layers.Dense(100, activation="relu"))
        model.add(keras.layers.Dropout(0.5))
        model.add(keras.layers.Dense(50, activation="relu"))
        model.add(keras.layers.Dropout(0.5))
        model.add(keras.layers.Dense(30, activation="relu"))
        model.add(keras.layers.Dropout(0.5))
        model.add(keras.layers.Dense(10, activation="softmax"))
    
        model.summary
        model.compile(loss="sparse_categorical_crossentropy",
              optimizer="Adamax",
              metrics=["accuracy"])
    
        history = model.fit(training_X, training_y, epochs=35,
                    validation_data=(test_X, test_y))
        model.save('DNN_model_30.h5')
        
        fold_ctr += 1
        break
    #시각화
    #plot_model(model, show_shapes=True, to_file="DNN_Model.png")
    #tf.keras.utils.plot_model(model)
    pd.DataFrame(history.history).plot(figsize=(12, 5))
    plt.grid(True)
    plt.gca().set_ylim(0, 1)
    plt.show()
     
    

    
#저장된 모델 확인후 불러옴
def scan_folder(path):
    if not os.path.exists("DNN_model_30.h5"):
        print("저장된 모델이 없습니다. \nMalware_paths와 Benignware_paths,\
              Evaluate를 설정하여 훈련된 모델을 만들어 주십시요. \n파일 스캔은 이후에 시도해주시길 바랍니다.")
        sys.exit(1)
    model = load_model('DNN_model_30.h5')
    
    def get_scan_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
        return targets

    test_paths = get_scan_paths(path)
    X = [get_str_features(path,hasher) for path in test_paths]
    
    X = np.array(X)
    
    X = X.reshape(-1, 1, 20000)
    _pred = model.predict_classes(X)
    
    
    
    _pred = list(_pred)
    
    _count = 0
    for k in _pred:
        if k == 1:
            _count += 1
            
    
    if 1 in _pred:
        print("멀웨어 갯수: ",_count)
        print("\n{0}\n \n0: 정상\n1: 멀웨어\n".format(_pred))
        print("*"*50)
        print("멀웨어로 예측된 파일이 발견되었습니다. \n파일을 삭제하고 싶으신가요? \ny / n")
    else:
        print("정상적인 폴더로 예측되었습니다.",_pred, sep="\n")
        
#처음 입력받은 값에 따라 실제로 실행되는 부분
if args.Scan_folder_path:
    scan_folder(args.Scan_folder_path)
elif args.Malware_paths and args.Benignware_paths:
    X, y = get_dataset(args.Benignware_paths,args.Malware_paths,hasher)
    model_learning(X,y,hasher)
else:
    print ("잘못된 입력입니다.\nMalware_paths와 Benignware_paths, \
           Evaluate를 설정하여 훈련된 모델을 만들어 주십시요.\n    \
           이후에 Scan_folder_path를 설정하여 해당폴더의 파일을 검사합니다.")
    parser.print_help()
    