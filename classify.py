import logging
import argparse
from general.settings import Settings
from ml.classifying import Classifier

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger()

def init_args():
    parser = argparse.ArgumentParser(description='Classifying Android apps with Scikit learn')
    parser.add_argument('--m', type=int, help='Amount of malware apps, which will be processed', default=10)
    parser.add_argument('--b', type=int, help='Amount of benign apps, which will be processed', default=10)
    parser.add_argument('--c', type=int, help='Use category for malware apps', default=-1)
    parser.add_argument('--f', type=int, help='Used features: static, dynamic_s, dynamic_i, hybrid_s, hybrid_i', default=3)

    args = parser.parse_args()
    Settings.MALWARE_AMOUNT = args.m
    Settings.BENIGN_AMOUNT = args.b
    Settings.MALWARE_CATEGORY = args.c
    Settings.FEATURE_TYPE = args.f

if __name__ == "__main__":
    init_args()
    c = Classifier() 
    c()

