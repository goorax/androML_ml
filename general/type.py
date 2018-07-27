from enum import Enum


class AppType(Enum):
    BENIGN = 0
    MALWARE = 1
    UNKNOWN = -1

class FeatureType(Enum):
    STATIC = 0
    DYNAMIC_S = 1
    DYNAMIC_I = 2
    HYBRID_S = 3
    HYBRID_I = 4
