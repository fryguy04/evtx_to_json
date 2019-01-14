#!/usr/bin/env python3
# File: evtx_to_json.py
# Author: Fred Frey
# Desc: Convert Windows Event Log files (*.evtx) to Json. 
#   By default takes 1 or more evtx files as an arg, converts to json and 
#   saves as same filename ending in .json
# 
# Credit: This code is Heavily pulled/influenced by 
#   Dan Gunter - https://github.com/dgunter/evtxtoelk. Most of the core code. Biggest change is I needed Evtx to Json not to ELK
#   Willi Ballenthin (@williballenthin) - Python module named python-evtx   
#
# Usage:
#   python3 evtxtojson.py  Microsoft-Windows-Sysmon%4Operational.evtx
#   (^^ will store output file Microsoft-Windows-Sysmon%4Operational.json)


import contextlib
import mmap
import traceback
import json
import argparse
from collections import OrderedDict
from datetime import datetime
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
import xmltodict
import sys
import os


class Evtx_To_Json:

    @staticmethod
    def evtx_to_json(filename, outfilename=''):
        evtx_json = []

        with open(filename) as infile:
            with contextlib.closing(mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                fh = FileHeader(buf, 0x0)
                data = ""
                for xml, record in evtx_file_xml_view(fh):
                    try:
                        contains_event_data = False
                        log_line = xmltodict.parse(xml)

                        # Format the date field
                        date = log_line.get("Event").get("System").get("TimeCreated").get("@SystemTime")
                        if "." not in str(date):
                            date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
                        else:
                            date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S.%f")
                        log_line['@timestamp'] = str(date.isoformat())
                        log_line["Event"]["System"]["TimeCreated"]["@SystemTime"] = str(date.isoformat())

                        # Process the data field to be searchable
                        data = ""
                        if log_line.get("Event") is not None:
                            data = log_line.get("Event")
                            if log_line.get("Event").get("EventData") is not None:
                                data = log_line.get("Event").get("EventData")
                                if log_line.get("Event").get("EventData").get("Data") is not None:
                                    data = log_line.get("Event").get("EventData").get("Data")
                                    if isinstance(data, list):
                                        contains_event_data = True
                                        data_vals = {}
                                        for dataitem in data:
                                            try:
                                                if dataitem.get("@Name") is not None:
                                                    data_vals[str(dataitem.get("@Name"))] = str(
                                                        str(dataitem.get("#text")))
                                            except:
                                                pass
                                        log_line["Event"]["EventData"]["Data"] = data_vals
                                    else:
                                        if isinstance(data, OrderedDict):
                                            log_line["Event"]["EventData"]["RawData"] = json.dumps(data)
                                        else:
                                            log_line["Event"]["EventData"]["RawData"] = str(data)
                                        del log_line["Event"]["EventData"]["Data"]
                                else:
                                    if isinstance(data, OrderedDict):
                                        log_line["Event"]["RawData"] = json.dumps(data)
                                    else:
                                        log_line["Event"]["RawData"] = str(data)
                                    del log_line["Event"]["EventData"]
                            else:
                                if isinstance(data, OrderedDict):
                                    log_line = dict(data)
                                else:
                                    log_line["RawData"] = str(data)
                                    del log_line["Event"]
                        else:
                            pass

                        evtx_json.append(log_line)

                        # If verbose then pretty print json to stdout
                        if(outfilename==''):
                            print(json.dumps(log_line, indent=2)) 
                            pass
                        else:
                            with open(outfilename, 'a') as outfile:
                                outfile.write(json.dumps(log_line))      
                    except:
                        print("***********")
                        print("Parsing Exception")
                        print(traceback.print_exc())
                        print(json.dumps(log_line, indent=2))
                        print("***********")

        return(evtx_json)


if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('evtxfile', nargs='+', help="Evtx file to parse")
    parser.add_argument('--stdout', action='store_true', default=False, help="Print to stdout instead of writing to file")

    # Parse arguments
    args = parser.parse_args()
    outfilename = ''

    # Loop through Files and Do the work! 
    for evtx_file in args.evtxfile:
        if(args.stdout):
            outfilename = ''
        else:
            outfilename = os.path.splitext(evtx_file)[0] + '.json'

        Evtx_To_Json.evtx_to_json(evtx_file, outfilename=outfilename)


