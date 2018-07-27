import argparse
import logging

from general.settings import Settings
from ml.clustering import Clustering

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger()

def init_args():
    parser = argparse.ArgumentParser(description='Cluster Android apps using scikit-learn and Virustotal tags')
    parser.add_argument('--m', type=int, help='Amount of malware apps, which will be processed', default=10)
    parser.add_argument('--b', type=int, help='Amount of benign apps, which will be processed', default=10)
    parser.add_argument('--csize', type=int, help='Set the used clustersize', default=20)
    parser.add_argument('--kmeans', help='Use Kmeans to cluster apps', action="store_true", default=True)
    args = parser.parse_args()
    Settings.MALWARE_AMOUNT = args.m
    Settings.BENIGN_AMOUNT = args.b
    Settings.CLUSTER_SIZE = args.csize
    Settings.CLUSTER_KMEANS = args.kmeans

if __name__ == "__main__":
    init_args()
    c = Clustering()
    c()

