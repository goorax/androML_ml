import logging
import graphviz 
import numpy as np
import pdb
import data.file_cacher as fc
import matplotlib.pyplot as plt
import heapq

from sklearn import tree
from pandas_ml import ConfusionMatrix
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import cross_val_predict
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
from sklearn.ensemble import RandomForestClassifier
from sklearn import preprocessing
from sklearn.linear_model import LogisticRegression
from ml.feature_processor import FeatureProcessor
from general.settings import Settings
from general.const import Consts
from sklearn.externals import joblib
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import AdaBoostClassifier, ExtraTreesClassifier
from sklearn.naive_bayes import MultinomialNB, GaussianNB, BernoulliNB
from sklearn.model_selection import cross_val_score, cross_validate
from sklearn.model_selection import ShuffleSplit
from sklearn.model_selection import KFold
from sklearn.decomposition import TruncatedSVD 
from sklearn.pipeline import Pipeline
from math import sqrt
from sklearn.model_selection import GridSearchCV

LOGGER = logging.getLogger()

class Classifier:
    """ This class Classifier handles classifying machine learning 
    techniques and operations 
    """

    def __init__(self):
        fp = FeatureProcessor()
        self.X, self.y = fp()
        self._print_info()   

    def _grid_search_test_train(self):
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(self.X, self.y, test_size=0.4, stratify=self.y, random_state=42)
        rf = RandomForestClassifier()
        param_grid = { 
            'n_estimators': [140,143,145],
            'max_features': ['sqrt', 'log2']}
        clf = GridSearchCV(rf, param_grid,cv=5, n_jobs=2)
        clf.fit(self.X_train, self.y_train)
        y_test_pred = clf.best_estimator_.predict(self.X_test)
        y_labels = [l for l in self.y_test ]
        _plot_cm()

    def _random_forest_export(self):
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(self.X, self.y, test_size=0.4, stratify=self.y, random_state=42)
        rf = RandomForestClassifier(n_estimators=140, max_depth=None, max_features="sqrt")
        rf.fit(self.X_train, self.y_train)
        fimportance = rf.feature_importances_.tolist()
        fdesc = fc.load_feature_description()
        pdb.set_trace()
        importance = heapq.nlargest(10, fimportance)
        importance_names = [fdesc[fimportance.index(value)] for value in importance]
        self._export_trees(rf, fdesc)

    def _plot_cm(self):
        cm = ConfusionMatrix(self.y_test, y_test_pred)
        cm.plot()
        plt.show()
        LOGGER.info(f'confusion matrix: {cm} ')
        pdb.set_trace()

    def _nested_cross_validation(self):
        rf = RandomForestClassifier()
        param_grid = { 
            'n_estimators': [100, 120, 140, 160],
            'max_features': ['sqrt', 'log2']}
        clf = GridSearchCV(rf, param_grid,cv=3, n_jobs=2)
        scores = cross_val_score(clf, self.X, self.y, cv=5)
        LOGGER.info(f'scores: {scores} ')
        LOGGER.info(f'score mean: %0.3f ' % scores.mean())
        pdb.set_trace()

    def __call__(self):
        #self._random_forest_export()
        #self._grid_search_test_train()
        self._nested_cross_validation()

    def _print_info(self):
        LOGGER.info(f'Shape of X: {self.X.shape}')
        LOGGER.info(f'Shape of y: {self.y.shape}')

        category = Settings.MALWARE_CATEGORY
        if category != -1:
            assigments, terms = fc.load_cluster_results()
            LOGGER.info(f'Amount of Malware of category {category}: {len(assigments[category])}')

    def _export_trees(self, forest):
        tree_count = 0
        for tree_in_forest in forest.estimators_:
            with open('tree_' + str(tree_count) + '.dot', 'w') as my_file:
                my_file = tree.export_graphviz(tree_in_forest, out_file = my_file, feature_names=fdesc)
                tree_count = tree_count + 1
                pdb.set_trace()


