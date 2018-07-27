from general.const import Consts
from general.settings import Settings

class App:

    def __init__(self, id, app_type, static_content, dynamic_content):
        self.id = id
        self.feature_type = Settings.FEATURE_TYPE
        self.app_type = app_type
        self.static_content = static_content
        # min_sdk, target_sdk, positives, total is ignored
        self.static_content_numerical_amount = len(static_content) - 4
        self.dynamic_content = dynamic_content
        self.dynamic_content_numerical_amount = len(dynamic_content)
        self._init_apk_meta_report(static_content)
        self._init_assets_report(static_content)
        self._init_bytecode_report(static_content)
        self._init_api_calls(dynamic_content)

    def _init_apk_meta_report(self, static_content):
        self.min_sdk = static_content[Consts.MIN_SDK]
        self.target_sdk = static_content[Consts.TARGET_SDK]
        self.permissions = static_content[Consts.PERMISSIONS]
        self.permission_amount = len(self.permissions)
        self.used_features = static_content[Consts.USED_FEATURES]
        self.used_features_amount = len(self.used_features)
        self.additional_permissions = static_content[Consts.ADDITIONAL_PERMISSIONS]
        self.additional_permissions_amount = len(self.additional_permissions)
        self.activities = static_content[Consts.ACTIVITIES]
        self.activities_amount = len(self.activities)
        self.services = static_content[Consts.SERVICES]
        self.services_amount = len(self.services)
        self.receivers = static_content[Consts.RECEIVERS]
        self.receivers_amount = len(self.receivers)
        self.providers = static_content[Consts.PROVIDERS]
        self.providers_amount = len(self.providers)
        self.intents = static_content[Consts.INTENTS]
        self.intents_amount = len(self.intents)

    def _init_assets_report(self, static_content):
        self.assets = static_content[Consts.ASSETS]
        self.assets_amount = len(self.assets)

    def _init_bytecode_report(self, static_content):
        self.filtered_class_names = static_content[Consts.FILTERED_CLASS_NAMES]
        self.filtered_class_names_amount = len(self.filtered_class_names)
        self.filtered_invoke_refs = static_content[Consts.FILTERED_INVOKE_REFS]
        self.filtered_invoke_refs_amount = len(self.filtered_invoke_refs)
        self.filtered_method_names = static_content[Consts.FILTERED_METHOD_NAMES]
        self.filtered_method_names_amount = len(self.filtered_method_names)
        self.filtered_uris = static_content[Consts.FILTERED_URIS]
        self.filtered_uris_amount = len(self.filtered_uris)
        self.total_classes_amount = static_content[Consts.TOTAL_CLASSES_AMOUNT]
        self.total_method_amount = static_content[Consts.TOTAL_METHOD_AMOUNT]
        self.total_package_amount = static_content[Consts.TOTAL_PACKAGE_AMOUNT]
        self.total_system_classes_amount = static_content[Consts.TOTAL_SYSTEM_CLASSES_AMOUNT]

    def _init_api_calls(self, dynamic_content):
        self.api_globals = dynamic_content[Consts.GLOBALS]
        self.api_globals_amount = len(self.api_globals)
        self.api_reflection = dynamic_content[Consts.REFLECTION]
        self.api_reflection_amount = len(self.api_reflection)
        self.api_generic = dynamic_content[Consts.GENERIC]
        self.api_generic_amount = len(self.api_generic)
        self.api_content = dynamic_content[Consts.CONTENT]
        self.api_content_amount = len(self.api_content)
        self.api_network = dynamic_content[Consts.NETWORK]
        self.api_network_amount = len(self.api_network)
        self.api_dex = dynamic_content[Consts.DEX]
        self.api_dex_amount = len(self.api_dex)
        self.api_crypto = dynamic_content[Consts.CRYPTO]
        self.api_crypto_amount = len(self.api_crypto)
        self.api_file = dynamic_content[Consts.FILE]
        self.api_file_amount = len(self.api_file)
        self.api_binder = dynamic_content[Consts.BINDER]
        self.api_binder_amount = len(self.api_binder)
        self.api_fingerprint = dynamic_content[Consts.FINGERPRINT]
        self.api_fingerprint_amount = len(self.api_fingerprint)
