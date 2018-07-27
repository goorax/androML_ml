import pdb
import logging

from elasticsearch import Elasticsearch
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl import Search
from general.const import Consts
from general.settings import Settings

LOGGER = logging.getLogger()

connections.create_connection(hosts=[Settings.ES_HOST_MACHINE], timeout=Settings.CONNECTION_TIMEOUT)
es = Elasticsearch([Settings.ES_HOST_MACHINE], timeout=Settings.CONNECTION_TIMEOUT)

def get_doc_from_db(db, id):
    LOGGER.info(f'Get doc {id} from db {db}')
    return es.get(index=db, doc_type=Consts.REPORT, id=id)

def get_ids_from_db(db, begin, end):
    amount = end - begin
    LOGGER.info(f'Get {amount} ids from db {db}')
    s = Search(using=es, index=db).source([])
    s = s[begin:end]
    ids = [h.meta.id for h in s]
    return ids

