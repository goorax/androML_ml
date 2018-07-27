import numpy as np
import pdb
import logging
import data.file_cacher as fc

from sklearn.externals import joblib
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer
from general.settings import Settings
from collections import defaultdict
from sklearn.externals import joblib
from sklearn.metrics import silhouette_score
LOGGER = logging.getLogger()

class Clustering:

    def __call__(self): 
        scan_results_raw = fc.load_cluster_data()
        self.scan_results = {id:' '.join(results).lower().replace("androidos", "").replace("android","")  for id, results in scan_results_raw.items()}
        self.ids = list(self.scan_results.keys())
        self._process()

    def _process(self):
        self.cv = CountVectorizer()
        results = self.cv.fit_transform(self.scan_results.values())
        tft = TfidfTransformer()
        results_tfidf = tft.fit_transform(results)
        if Settings.CLUSTER_KMEANS:
            #self._calc_silhouette_coefficient(results_tfidf)
            self._perform_kmeans(results_tfidf) 

    def _calc_silhouette_coefficient(self, results_tfidf):
        for k in range(90,101):
            kmeans = KMeans(n_clusters=k).fit(results_tfidf)
            label = kmeans.labels_
            coeff = silhouette_score(results_tfidf, label, metric='euclidean')
            LOGGER.info(f'Silhouette coefficient for k={k}: {coeff}')

    def _perform_kmeans(self, results_tfidf):    
        kmeans = KMeans(n_clusters=Settings.CLUSTER_SIZE).fit(results_tfidf)

        self._assign_ids_to_labels(kmeans)
        self._assign_terms_to_labels(kmeans)
        self._print_results()

    def _assign_ids_to_labels(self, kmeans):
        self.labels = list(kmeans.labels_)
        self.assignments = defaultdict(list)

        for i, l in enumerate(self.labels):
            self.assignments[l].append(self.ids[i])

    def _assign_terms_to_labels(self, kmeans): 
        self.order_centroids = kmeans.cluster_centers_.argsort()[:, ::-1]
        self.terms = self.cv.get_feature_names()

        self.category_terms = defaultdict(list)
        for i in range(Settings.CLUSTER_SIZE):
            for id in self.order_centroids[i, :10]:
                self.category_terms[i].append(self.terms[id])

    def _print_results(self):
        for i in range(Settings.CLUSTER_SIZE):
            print(f'Cluster {i} has {self.labels.count(i)} items: ')
            print(f'{self.assignments[i]}')
            for ind in self.order_centroids[i, :10]:
                print(f'Used terms: {self.terms[ind]}')
            print()

