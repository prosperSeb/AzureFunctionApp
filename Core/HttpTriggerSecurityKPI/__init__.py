import logging
import azure.functions as func
from ..Compute import *
from ..Merge import *
import os
import time
#test
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    start_merge_task_time = time.time()
    logging.info("start_merge_task")
    start_merge_task()
    compute_task_time = time.time()
    logging.info("Time consumed in merge: " + str(compute_task_time - start_merge_task_time))
    logging.info("compute_task")
    compute_task()
    end_time = time.time()
    logging.info("Time consumed in compute: " + str(end_time - compute_task_time))

    return func.HttpResponse(
            "Done",
            status_code=200
    )
