import logging
import sys
import os
import re
from threading import Thread
from io import StringIO
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import datetime

sys.stdout.reconfigure(encoding='utf-8')

def merge_files(report_type, report_date):
    connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)

    container_client = blob_service_client.get_container_client('csv')
    Filename = ("Azure-%s.csv") % report_type[:-7]
    Output = "%s%s" % (report_date, Filename)

    stroutput = ""
    try:
        nb_file = 0
        pattern = re.compile(report_date + ".*-" + Filename, re.IGNORECASE)
        for blob in container_client.walk_blobs(name_starts_with=report_date, delimiter="/"):
            # if (pattern.match(blob.name) and (blob.name != (report_date + "Azure-" + Filename))):
            if (pattern.match(blob.name)):
                obj = container_client.download_blob(blob.name, encoding='utf8')
                text = obj.content_as_text()
                buf = StringIO(text)
                nb_line = 0
                for line in buf.readlines():
                    if nb_file == 0 or nb_line > 0:
                        if line[-1] != '\n':
                            line += '\n'
                        stroutput = stroutput + line
                    nb_line += 1
                nb_file += 1
    except Exception as e:
        logging.exception(e)
    if (len(stroutput) > 0):
        container_client.upload_blob(name=Output, data=stroutput, overwrite=True)

def import_exception(blob_service_client):
    container_client = blob_service_client.get_container_client('exception')
    cur_date = datetime.datetime.now().strftime('%Y-%m-%d/')
    for blob in container_client.walk_blobs(name_starts_with="validated-exception/", delimiter="/"):
        pattern = re.compile(r".*-" + "Azure-Exceptions.csv", re.IGNORECASE)
        if (pattern.match(blob.name)):
            test = container_client.get_blob_client(blob)
            filename = blob.name.split('/')[-1]
            output = "ExceptionsReport/" + cur_date + filename
            copied_blob = blob_service_client.get_blob_client("csv", output)
            copied_blob.start_copy_from_url(test.url)


def start_merge_task():
    connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)
    import_exception(blob_service_client)
    container_client = blob_service_client.get_container_client('csv')
    MergeThreads = {}
    for report_type in container_client.walk_blobs(name_starts_with=None, delimiter="/"):
        if ('Report' in report_type.name):
            for report_date in container_client.walk_blobs(name_starts_with=report_type.name, delimiter="/"):
                pass
            MergeThreads[report_type.name] = (Thread(target = merge_files, args=(report_type.name, report_date.name)))
            MergeThreads[report_type.name].start()
    for report_type in MergeThreads:
        MergeThreads[report_type].join()

#Local Run:
# start_merge_task()