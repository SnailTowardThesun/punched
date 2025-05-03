# Author: hankun1991@outlook.com
from pmg_inference.models.yolo import YoloWorker


def test_yolo():
    yolo = YoloWorker()
    yolo.process()