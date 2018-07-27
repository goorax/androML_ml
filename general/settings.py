
class Settings:

    ES_HOST_MACHINE = 'localhost'
    CONNECTION_TIMEOUT = 900
    
    MALWARE_CATEGORY = -1
    MALWARE_AMOUNT = 4000
    BENIGN_AMOUNT = 5000
    FEATURE_TYPE = 3

    BENIGN_THRESHOLD = 2    

    CACHE_ROOT = 'cache/'
    CACHE_CLUSTERING = CACHE_ROOT + 'clustering/'
    CACHE_IDS = CACHE_ROOT + 'ids/'
    CACHE_APPS = CACHE_ROOT + 'apps/'
    CACHE_FEATURE_NAMES = CACHE_ROOT + 'feature_names/'
    CACHE_MATRICES = CACHE_ROOT + 'matrices/'
    CACHE_SCAN_RESULTS = CACHE_ROOT + 'scan_results/'
    CACHE_TREES = CACHE_ROOT + 'trees/'

    REBUILD = False
    BUCKETS = 10

    CLUSTER_SIZE = 27
    CLUSTER_KMEANS = True
