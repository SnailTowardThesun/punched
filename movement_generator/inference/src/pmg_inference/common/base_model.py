# Author: hankun1991@outlook.com

import logging

class BaseModelWorker:
    def __init__(self):
        logging.info(f'base model worker init')

    def process(self, **kwargs):
        assert False, "process is an abstract method"