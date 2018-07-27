import pytest
import pdb

from general.settings import Settings
from general.const import Consts
from data.app_builder import AppBuilder

SAMLE_MALWARE = '32f27a471ad597ff5911dc71daf27f52b32d9328930596759c310e487982a003'
SAMLE_BENIGN = 'e5c3661566882cf487eec7125d7d540ece1fb232b52abf69fc0a9a524933cb9aq'
SAMPLE_BENIGN_DB = Consts.DYNAMIC_SIMPLE_BENIGN
SAMPLE_MALWARE_DB = Consts.DYNAMIC_SIMPLE_MALWARE


def test_get_ids():
    ids = ea.get_ids_from_db(DYNAMIC_INDEX, begin, end)
    assert len(ids) == 10

def test_feature_processor():
    Settings.BENIGN_AMOUNT = 1
    Settings.MALWARE_AMOUNT = 1

def test_get_app_with_features():
    ab = AppBuilder()
    app = ab.build_app(STATIC_INDEX, DYNAMIC_INDEX, id=ELASTIC_ID)
    assert app.id == ELASTIC_ID
    assert app.used_features == [{'name': 'android.hardware.camera', 'required': False}, {'name': 'android.hardware.touchscreen', 'required': False}, {'name': 'android.hardware.screen.portrait', 'required': False}, {'name': 'android.hardware.wifi', 'required': False}]
    assert app.min_sdk == '11'
    assert app.target_sdk == '25'

def test_dynamic_feature_collector():
    keys_tobe = ['globals', 'reflection', 'generic', 'content', 'network', 'dex', 'crypto', 'file', 'binder', 'fingerprint']
    ab = AppBuilder()
    dynamic_features = ab._get_dynamic_analysis_result(DYNAMIC_INDEX, ELASTIC_ID)
    result_set = set(dynamic_features.keys()).intersection(keys_tobe)
    assert len(result_set) == 10

def test_static_feature_collector():
    ab = AppBuilder()
    static_features = ab._get_static_analysis_result(STATIC_INDEX, ELASTIC_ID)
    assert len(static_features) == 19

def test_get_specific_app():
    app_id = '1db5ff5534c001aa670dcb3f58d6cb4e019781662ebd32d73ec054c06f798338'
    ab = AppBuilder()
    app = ab.build_app(STATIC_INDEX, DYNAMIC_INDEX, app_id)
    pdb.set_trace()
    assert app.id == app_id


