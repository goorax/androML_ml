import json
import pdb
import logging

from general.type import FeatureType
from general.type import AppType
from general.const import Consts
from general.settings import Settings
from structs.app import App
import data.db_adapter as db

LOGGER = logging.getLogger()

class AppBuilder:
    """ This class will build an App instance and collect static
    and dynamic features through database access.
    """

    def _get_static_analysis_result(self, index, id):
        static_content = dict()
        response = db.get_doc_from_db(index, id)
        if (Consts.SOURCE in response):
            static_content = self._get_static_content(response, static_content)
        return static_content

    def _get_dynamic_analysis_result(self, index, id):
        api_log = self._get_dynamic_analysis_as_json(index, id)
        dynamic_content = self._classify_api_calls(api_log)
        return dynamic_content

    def _get_static_content(self, response, static_content):
           source = response[Consts.SOURCE]
           self._get_apk_meta_report_content(static_content, source)
           self._get_assets_report_content(static_content, source)
           self._get_bytecode_report_content(static_content, source)
           self._get_virustotal_report_content(static_content, source)
           return static_content

    def _get_apk_meta_report_content(self, static_features, source):
           apk_meta_report = source[Consts.APK_META_REPORT]
           if (Consts.MIN_SDK in apk_meta_report):
               static_features[Consts.MIN_SDK] = apk_meta_report[Consts.MIN_SDK]
           else:
               static_features[Consts.MIN_SDK] = ''
           if (Consts.TARGET_SDK in apk_meta_report):
               static_features[Consts.TARGET_SDK] = apk_meta_report[Consts.TARGET_SDK]
           else:
               static_features[Consts.TARGET_SDK] = ''
           static_features[Consts.PERMISSIONS] = apk_meta_report[Consts.PERMISSIONS]
           static_features[Consts.USED_FEATURES] = apk_meta_report[Consts.USED_FEATURES]
           static_features[Consts.ADDITIONAL_PERMISSIONS] = apk_meta_report[Consts.ADDITIONAL_PERMISSIONS]
           static_features[Consts.ACTIVITIES] = apk_meta_report[Consts.ACTIVITIES]
           static_features[Consts.SERVICES] = apk_meta_report[Consts.SERVICES]
           static_features[Consts.RECEIVERS] = apk_meta_report[Consts.RECEIVERS]
           if (Consts.PROVIDERS in apk_meta_report):
                static_features[Consts.PROVIDERS] = apk_meta_report[Consts.PROVIDERS]
           else:
                static_features[Consts.PROVIDERS] = []
           if (Consts.INTENTS in apk_meta_report):
                static_features[Consts.INTENTS] = apk_meta_report[Consts.INTENTS]
           else:
               static_features[Consts.INTENTS] = []

    def _get_assets_report_content(self, static_features, source):
           if (Consts.ASSETS_REPORT in source):
                assets_report = source[Consts.ASSETS_REPORT]
                static_features[Consts.ASSETS] = assets_report[Consts.ASSETS]
           else:
               assets_report = {Consts.ASSETS: []}
               static_features[Consts.ASSETS] = assets_report[Consts.ASSETS]

    def _get_bytecode_report_content(self, static_features, source):
           bytecode_report = source[Consts.BYTECODE_REPORT]
           static_features[Consts.FILTERED_CLASS_NAMES] = bytecode_report[Consts.FILTERED_CLASS_NAMES]
           static_features[Consts.FILTERED_INVOKE_REFS] = bytecode_report[Consts.FILTERED_INVOKE_REFS]
           static_features[Consts.FILTERED_METHOD_NAMES] = bytecode_report[Consts.FILTERED_METHOD_NAMES]
           static_features[Consts.FILTERED_URIS] = bytecode_report[Consts.FILTERED_URIS]
           static_features[Consts.TOTAL_CLASSES_AMOUNT] = bytecode_report[Consts.TOTAL_CLASSES_AMOUNT]
           static_features[Consts.TOTAL_METHOD_AMOUNT] = bytecode_report[Consts.TOTAL_CLASSES_AMOUNT]
           static_features[Consts.TOTAL_PACKAGE_AMOUNT] = bytecode_report[Consts.TOTAL_PACKAGE_AMOUNT]
           static_features[Consts.TOTAL_SYSTEM_CLASSES_AMOUNT] = bytecode_report[Consts.TOTAL_SYSTEM_CLASSES_AMOUNT]

    def _get_virustotal_report_content(self, static_features, source):
           virustotal_report = source[Consts.VIRUSTOTAL_REPORT]
           if (Consts.POSITIVES in virustotal_report):
                static_features[Consts.POSITIVES] = virustotal_report[Consts.POSITIVES]
           if (Consts.TOTAL in virustotal_report):
                static_features[Consts.TOTAL] = virustotal_report[Consts.TOTAL]
           self._include_scan_results(static_features, virustotal_report) 

    def _include_scan_results(self, static_features, virustotal_report):
        if (Consts.POSITIVES in virustotal_report and static_features[Consts.POSITIVES] >= Settings.BENIGN_THRESHOLD):
            static_features[Consts.SCAN_RESULTS] = [scan['result'] for scan in virustotal_report['scans'].values() if 'result' in scan and scan['result'] != None]
        else:
            static_features[Consts.SCAN_RESULTS] = []

    def _get_dynamic_analysis_as_json(self, index, id):
        response = db.get_doc_from_db(index, id)
        if (Consts.SOURCE in response):
            api_log = f'[{response[Consts.SOURCE][Consts.API_CALLS]}]'
            return json.loads(api_log)

    def _classify_api_calls(self, api_log):
        classified_api_calls = {'globals':[], 'reflection':[], 'generic':[], 'content':[], 'network':[], 'dex':[], 'crypto':[], 'file':[], 'binder':[], 'fingerprint':[]}
        for api_call in api_log:
            if (api_call[Consts.TYPE] in classified_api_calls):
                classified_api_calls[api_call[Consts.TYPE]].append(api_call)
        return classified_api_calls

    def _determine_index(self, type):
        ft = Settings.FEATURE_TYPE
        if type == 'benign':
            if ft == FeatureType.HYBRID_S.value:
                return Consts.STATIC_INDEX_BENIGN, Consts.DYNAMIC_INDEX_BENIGN
            if ft == FeatureType.HYBRID_I.value:
                return Consts.STATIC_INDEX_BENIGN, Consts.DYNAMIC_INDEX_IA_BENIGN
        elif type == 'malware':
            if ft == FeatureType.HYBRID_S.value:
                return Consts.STATIC_INDEX_MALWARE, Consts.DYNAMIC_INDEX_MALWARE
            if ft == FeatureType.HYBRID_I.value:
                return Consts.STATIC_INDEX_MALWARE, Consts.DYNAMIC_INDEX_IA_MALWARE

    def _determine_app_type(self, positives):
        if (positives <= Settings.BENIGN_THRESHOLD):
            app_type = AppType.BENIGN
        else:
            LOGGER.info(f'Malware app positives: %d', positives)
            app_type = AppType.MALWARE
        return app_type

    def build_app(self, id, type):
        LOGGER.info(f'Build app with id: {id}')
        static_index, dynamic_index = self._determine_index(type)
        static_result = self._get_static_analysis_result(static_index, id)
        dynamic_result = self._get_dynamic_analysis_result(dynamic_index, id)
        if (Consts.POSITIVES in static_result):
            positives = static_result[Consts.POSITIVES]
            app_type = self._determine_app_type(positives)
            return App(id, app_type, static_result, dynamic_result)
        else:
            return App(id, AppType.UNKNOWN, static_result, dynamic_result)

