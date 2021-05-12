# TODO: Handle files with same name -> hash based name dir and file?
import queue

import magic
import yara
import os.path
import logging
import sys
import argparse
import hashlib
import subprocess
import json
import uuid
import os
import re
import pefile
import peutils
import time
import multiprocessing

from datetime import datetime
from shutil import copyfile
from copy import deepcopy

import capa.main
import capa.rules
from capa.render import convert_capabilities_to_result_document

RULES_PATH = f"files{os.sep}capa-rules"

# should most likely make a global variables init function. ¯\_(ツ)_/¯
STRINGS_PATH = "strings.txt"
with open(STRINGS_PATH, "r") as fp:
    STRINGS_LIST = fp.readlines()

FUNCTIONS_PATH = "functions.txt"
with open(FUNCTIONS_PATH, "r") as fp:
    FUNCTIONS_LIST = fp.readlines()

WORK_DIR = "picky_analysis"
NUMBERS_OF_CORES_TO_USE = 4

# disable logging to suppress capa
logging.disable(level=logging.WARNING)
# loading rules
RULES = capa.main.get_rules(RULES_PATH, disable_progress=True)
RULES = capa.rules.RuleSet(RULES)

PEID_RULES = yara.compile(f"files{os.sep}peid.yar")

# regex expressions gotten from https://gchq.github.io and re-search.py by Didier Stevens
REGEX_EXPRESSIONS = {
    "regex_ipv4": r"(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?",
    #"regex_ipv6": r"((?=.*::)(?!.*::.+::)(::)?([\dA-Fa-f]{1,4}:(:|\b)|){5}|([\dA-Fa-f]{1,4}:){6})((([\dA-Fa-f]{1,4}((?!\3)::|:\b|(?![\dA-Fa-f])))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})",
    "regex_email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}",
    "regex_url": r"[a-zA-Z]+://[_-a-zA-Z0-9.]+(?:/[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?(?:\?[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?",
    "regex_btc": r"(?#extra=P:BTCValidate)\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "regex_onion": r"[a-zA-Z2-7]{16}\.onion"
}

# List of analyzed files, combat duplicate analysis
ANALYZED_FILES = list()

#logger = logging.getLogger("picky")


# Creating custom exception handling to abort object creation on duplicate
class Error(Exception):
    pass


class AlreadyAnalyzed(Error):
    pass


class UnwantedPacker(Error):
    pass


class AnalyzeFile:
    def __init__(self, path: str):
        global ANALYZED_FILES

        self.path = os.path.abspath(path)
        self.filename = os.path.basename(self.path)
        self.binary_data = self.__get_content(self.path)
        self.hashes = dict()
        self.peid = ""
        self.capa_dict = dict()
        self.floss = dict()
        self.pedata = ""
        self.tags_list = list()
        self.capa_tags = dict()

        # use hashes md5 to create unique folder and file name
        self.__calculate_hashes()
        # So there is some fuckup when doing single and multiprocess, checking for abs path
        if WORK_DIR[1] == ":":
            self.working_dir = WORK_DIR + os.sep + self.hashes["md5"]
        else:
            self.working_dir = os.path.dirname(self.path) + os.sep + WORK_DIR + os.sep + self.hashes["md5"]

        # Checking for unwanted packers
        self.peid = self.__yara_peid()
        for match in self.peid:
            if "delphi" in match.lower():
                print("[!] Unwanted delphi packed sample!")
                raise UnwantedPacker

        # creating working directory
        check_mkdir(self.working_dir)
        # Copy and rename file to more unique and identifiable
        copyfile(self.path, self.working_dir + os.sep + self.hashes["md5"] + ".PE")
        # rewrite self.path to new file
        self.path = self.working_dir + os.sep + self.hashes["md5"] + ".PE"

        # Populating analysis
        self.floss = FLOSSAnalysis(self.path, self.working_dir)

        capa_analysis = CapaAnalysis(self.path)
        self.capa_dict = capa_analysis.capa_dict

        self.pedata = PEDataAnalysis(self.path)

        return

    def __get_content(self, path: str) -> bin:
        with open(path, "rb") as fp:
            content = fp.read()
        return content

    def __yara_peid(self) -> list:
        tmp = PEID_RULES.match(self.path)
        ret_list = list()
        for el in tmp:
            ret_list.append(el.rule)
        return ret_list

    def __calculate_hashes(self) -> None:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        md5.update(self.binary_data)
        self.hashes["md5"] = md5.hexdigest()
        sha1.update(self.binary_data)
        self.hashes["sha1"] = sha1.hexdigest()
        sha256.update(self.binary_data)
        self.hashes["sha256"] = sha256.hexdigest()

    def pprint(self):
#        print(f"""Filename: {self.filename}
#Hashes:
#  md5: {self.hashes["md5"]}
#  sha1: {self.hashes["sha1"]}
#  sha256: {self.hashes["sha256"]}
#PEid: {", ".join(self.peid)}""")
#        print("Interesting Strings:\n  Static:\n    " + "\n    ".join(self.floss.interesting_strings["static"]))
#        print("  Decoded:\n    " + "\n    ".join(self.floss.interesting_strings["decoded"]))
#        print("  Stack:\n    " + "\n    ".join(self.floss.interesting_strings["stack"]))
#        print("Interesting Imports:")
#        print("  " + "\n  ".join(self.pedata.interesting_imports))
#        print("Done")
        print(self.create_report())
        print("Done!")

    def create_report(self) -> str:
        self.__generate_tags()
        final_report = f"Filname: {self.filename}\n" \
                       f"Path to file: {self.path}\n" \
                       f"Hashes:\n" \
                       f"  MD5:\t\t{self.hashes['md5']}\n" \
                       f"  SHA1:\t\t{self.hashes['sha1']}\n" \
                       f"  SHA256:\t{self.hashes['sha256']}\n\n" \
                       f"Tags: {', '.join(self.tags_list)}\n" \
                       f"Tags (subset from capa): {', '.join(self.capa_tags)}\n\n" \
                       f"PeID: {', '.join(self.peid) if self.peid else 'No signature hits'}\n" \
                       f"PE Metadata analysis:\n" \
                       f"  Is 32-bit: {'Yes' if self.pedata.is32bit else 'No'}\t\t\t" \
                       f"Is dll: {'Yes' if self.pedata.isdll else 'No'}\n" \
                       f"  Is probably packed: {'Yes' if self.pedata.probably_packed else 'No'}\t" \
                       f"Has TLS section: {'Yes' if self.pedata.tls else 'No'}\n" \
                       f"  Sections:\n"
        # Analyzing section data
        something_unusual = False
        for sect_name, analysis in self.pedata.section_analysis.items():
            if analysis["unusual_name"]:
                ana_text = "Unusual section name -> "
            elif analysis["unusual_permissions"]:
                ana_text = "Unusual permissions -> "
            elif analysis["raw_virtual_size_diff"]:
                ana_text = "Unusual large difference in raw and virtual size -> "
            else:
                continue

            something_unusual = True
            ana_text += f"Section name: {sect_name} - " \
                        f"Permissions: {', '.join(analysis['permissions'])} - " \
                        f"Large raw and virtual size diff: " \
                        f"{'Yes' if analysis['raw_virtual_size_diff'] else 'No'} - " \
                        f"Section entropy: {analysis['entropy']:.3f}\n"
            final_report += f"    {ana_text}"
        if not something_unusual:
            ana_text = "NTB with sections."
            final_report += f"    {ana_text}"

        # getting interesting functions
        final_report += "\n\nPotentially interesting imports from IAT:\n  " + '\n  '.join(self.pedata.interesting_imports) + '\n'

        final_report += "\n\nPotentially interesting strings:\n  "
        final_report += "Static:\n    " + '\n    '.join(self.floss.interesting_strings["static"])
        final_report += "\n  Decoded:\n    " + '\n    '.join(self.floss.interesting_strings["decoded"])
        final_report += "\n  Stack Strings:\n    " + '\n    '.join(self.floss.interesting_strings["stack"])
        final_report += "\n\n"

        final_report += "Capa analysis findings:\n"
        final_report += json.dumps(self.capa_dict, indent=4, sort_keys=True)
        final_report += "\n\n"

        final_report += "All strings:\n"
        final_report += json.dumps(self.floss.json["strings"], indent=4, sort_keys=True)
        final_report += "\n\n"

        # import and export
        final_report += "Staticlly imported functions:\n  " + ' \n  '.join(self.pedata.import_list) + '\n'
        final_report += f"Statically exported functions:\n  " + '\n  '.join(self.pedata.export_list) + '\n'

        return final_report

    def __generate_tags(self) -> None:
        tags = {
            "exe": False,
            "dll": False,
            "tls": False,
            "exports": False,
            "exe_with_exports": False,
            "few_imports": False,
            "packed": False,
            "unusual_section_name": False,
            "unusual_section_permissions": False,
            "raw_virtual_size_diff": False,
            "interesting_stack_strings": False,
            "stack_strings": False,
            "interesting_decoded_string": False,
            "decoded_strings": False,
            "decoded_function_names": False,
            "interesting_static_strings": False,
            "network": False,
            "keylogger": False,
            "ransomware": False,
            "anti_vm": False,
            "anti_disasm": False,
            "anti_debugging": False,
            "anti_analysis_tools": False,
            "anti_av": False,
            "indirect_call": False,
            "registry": False
        }
        if self.pedata.isdll:
            tags["dll"] = True
        else:
            tags["exe"] = True

        tags["tls"] = self.pedata.tls
        tags["exports"] = len(self.pedata.export_list) > 0
        tags["exe_with_exports"] = True if tags["exe"] and tags["exports"] else False
        tags["few_imports"] = True if len(self.pedata.import_list) <= 15 else False
        tags["packed"] = self.pedata.probably_packed
        for section in self.pedata.section_analysis.values():
            if section["unusual_name"]:
                tags["unusual_section_name"] = True
            if section["unusual_permissions"]:
                tags["unusual_section_permissions"] = True
            if section["raw_virtual_size_diff"]:
                tags["raw_virtual_size_diff"] = True
        tags["stack_strings"] = True if len(self.floss.json["strings"]["stack_strings"]) > 0 else False
        tags["interesting_stack_strings"] = True if len(self.floss.interesting_strings["stack"]) > 0 else False
        tags["decoded_strings"] = True if len(self.floss.json["strings"]["decoded_strings"]) > 0 else False
        tags["interesting_decoded_string"] = True if len(self.floss.interesting_strings["decoded"]) > 0 else False
        tags["interesting_static_strings"] = True if len(self.floss.interesting_strings["static"]) > 0 else False
        tags["decoded_function_names"] = self.floss.decoded_function_names

        capa_rule_name_tagging = {
            "anti_debugging": ["debug", "ntglobalfalg", "breakpoint", "heap flags", "heap force flags"],
            "anti_av": ["sandbox"],
            "anti_disasm": ["heavens", "anti-disasm"],
            "anti_vm": ["anti-vm", "memory capacity"],
            "anti_analysis_tools": ["analysis tools"],
            "stack_strings": ["stackstrings"],
            "packed": ["packed"],
            "shell": ["shell"],
            "execute": ["execute"],
            "keylogger": ["keystroke", "clipboard"],
            "network": ["recieve", "wininet", "winhttp", "http", "url", "internet", "sock", "tcp", "udp", "dns",
                        "domain information", "network"],
            "xor": ["xor"],
            "base64": ["base64"],
            "rc4": ["rc4"],
            "aes": [" aes "],
            "des": [" des "],
            "rsa": [" rsa "],
            "embeded_pe": ["embedded pe"],
            "ransomware": ["enumerate files", "enumerate disk volumes"],
            "firewall": ["firewall"],
            "desktop_lock": ["lock the desktop"],
            "change_wallpaper": ["wallpaper"],
            "cpu_info": ["cpu information", "number of processors"],
            "mutex": ["mutex"],
            "create_process_suspended": ["process suspended"],
            "rwx_memory": ["rwx memory"],
            "registry": ["registry"],
            "start_service": ["create service", "run as service", "start service"],
            "create_thread_suspended": ["suspend thread"],
            "create_process": ["create process"],
            "destructive": ["delete volume", "overwrite master boot"],
            "pusha_popa": ["pusha popa"],
            "peb": ["peb "],
            "dynamic_resolved_functions": ["link function at runtime"],
            "persistence": ["persist", "scheduled"]
        }

        for rule_name in self.capa_dict.keys():
            for tag, match_list in capa_rule_name_tagging.items():
                for match in match_list:
                    if match in rule_name.lower():
                        if rule_name in self.capa_tags.keys():
                            self.capa_tags[rule_name].append(tag)
                        else:
                            self.capa_tags[rule_name] = [match]
                        # updateing normal tag dict
                        if tag in tags.keys():
                            tags[tag] = True

        for tag, value in tags.items():
            if value:
                self.tags_list.append(tag)

    def write_report(self):
        with open(f"{self.working_dir}{os.sep}PickyReport_{os.path.basename(self.path)}.txt", "w") as fp:
            fp.write(self.create_report())


class CapaAnalysis:
    def __init__(self, path):
        self.path = path
        self.capa_dict = dict()

        self.__capa_analysis()

    def __capa_analysis(self) -> None:
        extractor = capa.main.get_extractor(self.path, "auto", "", "",  disable_progress=True)
        capabilities, counts = capa.main.find_capabilities(RULES, extractor, disable_progress=True)

        doc = convert_capabilities_to_result_document("", RULES, capabilities)

        #rule_hit_loc = dict()
        for rule_name, rule_dict in doc["rules"].items():
            self.capa_dict[rule_name] = dict()
            for match in rule_dict["matches"].values():
                temp = self.__recursive_get_lowest_child_location(match)
                for m in temp:
                    for hit, locs in m.items():
                        tmp_loc_list = self.capa_dict[rule_name].get(hit, list())
                        self.capa_dict[rule_name].update({hit: tmp_loc_list + locs})
            # if there arent anything populated, delete the entry
            if not self.capa_dict[rule_name]:
                del self.capa_dict[rule_name]

    def __recursive_get_lowest_child_location(self, entry: dict) -> list:
        # if success is false, then leave
        if not entry["success"]:
            return [{}]

        dict_key = ""   # for syntax highlight
        # if has success and no more children, then we are lowest
        if entry["success"] and entry["children"] == []:
            # trying to extract API call
            # test if feature key
            if "feature" in entry["node"]:
                if "api" in entry["node"]["feature"]:
                    dict_key = entry["node"]["feature"]["api"]
                elif "characteristic" in entry["node"]["feature"]:
                    want_list = ["indirect call", "nzxor", "peb access", "stack string"]
                    ignore_list = ["loop", "tight loop", "recursive call"] # more for debug more that anything
                    if entry["node"]["feature"]["characteristic"] in want_list:
                        dict_key = entry["node"]["feature"]["characteristic"]
                    elif entry["node"]["feature"]["characteristic"] in ignore_list:
                        return [{}]
                    else:
                        print("unseen charac or something")
                        return [{}]
                elif "regex" in entry["node"]["feature"]:
                    dict_key = entry["node"]["feature"]["match"]
                elif "mnemonic" in entry["node"]["feature"]:
                    want_inst = ["sidt", "sgdt", "sldt", "smsw", "str", "in", "vpcext", "int", "aesenc", "aesdec"]
                    if entry["node"]["feature"]["mnemonic"] in want_inst:
                        dict_key = entry["node"]["feature"]["mnemonic"]
                    else:
                        return [{}]
                else:
                    # type number, section, bytes??, offset, offset/x32
                    return [{}]
            elif "statement" in entry["node"]: # range
                if "range" in entry["node"]["statement"]:
                    if "child" in entry["node"]["statement"]:
                        if "api" in entry["node"]["statement"]["child"]:
                            dict_key = entry["node"]["statement"]["child"]["api"]
                else:
                    # unhandle statement
                    return [{}]
            else:
                # no feature
                return [{}]
            locs = [hex(loc) for loc in entry["locations"]]

            # returns a small list with dict with found item at locations. Ret list for ease of handling
            return [{dict_key: locs}]

        else:
            # gives nested list. check and unnest
            children_matches = list()
            for child in entry["children"]:
                tmp = self.__recursive_get_lowest_child_location(child)
                if tmp:
                    children_matches.append(tmp)

            unnest = list()
            for el in flatten_list(children_matches):
                unnest.append(el)
            return unnest


class FLOSSAnalysis:
    def __init__(self, path: str, workdir: str):
        self.path = path
        self.filename = os.path.basename(self.path)
        self.workdir = workdir
        self.json = dict()
        self.interesting_strings = dict()
        self.decoded_function_names = False

        self.__run_floss()
        self.__save_json()
        self.__string_analysis()

    def __run_floss(self):
        # Forgive me father, for I have sinned.
        tempjson = f"{str(uuid.uuid4())}_tmp.json"
        result = subprocess.run([f"files{os.sep}floss.exe", "-q", "-o", tempjson, self.path],
                                capture_output=True)
        with open(tempjson, "r") as fp:
            self.json = json.load(fp)

        os.remove(tempjson)

    def __save_json(self):
        with open(f"{self.workdir}{os.sep}floss_output_{self.filename}.json", "w") as fp:
            fp.write(json.dumps(self.json, indent=4, sort_keys=True))

    def __matching(self, string_list: list, function_names: bool = False) -> list:
        matches_list = list()
        for s in string_list:
            s_lower = s.lower()
            for match in STRINGS_LIST:
                if match.startswith("#"):
                    continue
                if match.lower().rstrip("\n") in s_lower:
                    if s not in matches_list:
                        matches_list.append(s)
            # Extend search with function list, useful with decoded or stack strings.
            if function_names:
                for func in FUNCTIONS_LIST:
                    if func.startswith("#"):
                        continue
                    if func.lower().rstrip("\n") in s_lower:
                        if s not in matches_list:
                            self.decoded_function_names = True
                            matches_list.append(s)

        tmp_str = "\n".join(string_list)
        for regexname, regexexp in REGEX_EXPRESSIONS.items():
            findall = re.findall(regexexp, tmp_str)
            if findall:
                findall_str = ", ".join(findall)
                matches_list.append(f"Regex->{regexname}: {findall_str}")

        return matches_list

    def __string_analysis(self):
        # Could ofc create some complex matching algorithm, buuuut...
        interesting_static = self.__matching(self.json["strings"]["static_strings"])
        interesting_decoded = self.__matching(self.json["strings"]["decoded_strings"], function_names=True)
        interesting_stack = self.__matching(self.json["strings"]["stack_strings"], function_names=True)

        self.interesting_strings = {"static": interesting_static,
                                    "decoded": interesting_decoded,
                                    "stack": interesting_stack
                                    }


class PEDataAnalysis:
    def __init__(self, path: str):
        self.path = path
        self.pedata = pefile.PE(self.path, fast_load=True)
        self.import_list = list()
        self.export_list = list()
        self.interesting_imports = list()
        self.section_analysis = dict()
        self.tls = False
        self.isdll = self.pedata.is_dll()
        self.is32bit = True if self.pedata.FILE_HEADER.Machine == 0x14c else False
        self.probably_packed = False

        self.__analyze()

    def __get_imports_exports(self):
        if self.pedata.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
            try:
                self.pedata.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                if self.pedata.DIRECTORY_ENTRY_IMPORT is not None:
                    for entry in self.pedata.DIRECTORY_ENTRY_IMPORT:
                        for imptab in entry.imports:
                            if imptab.name is None:
                                if imptab.ordinal is None:
                                    imptab.name = "None"
                                else:
                                    imptab.name = "Ordinal: " + str(imptab.ordinal)
                            # decode name if bytes
                            imp_func = imptab.name.decode() if type(imptab.name) == bytes else imptab.name
                            self.import_list.append(imp_func)
                else:
                    self.import_list.append("No imports?")
            except KeyError:
                self.import_list = []

            try:
                self.pedata.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORTS']])
                if self.pedata.DIRECTORY_ENTRY_EXPORT is not None:
                    for entry in self.pedata.DIRECTORY_ENTRY_EXPORT.symbols:
                        for exptab in entry:
                            if exptab.name is None:
                                if imptab.ordinal is None:
                                    exptab.name = "No name no ordinal"
                                exptab.name = "Ordinal: " + str(exptab.ordinal)
                            exptab.name = f"{exptab.name} - Ordinal: {str(exptab.ordinal)}"
                            self.export_list.append(exptab.name)
            except KeyError:
                self.export_list = []

    def __import_analysis(self):
        for imp in self.import_list:
            for match in FUNCTIONS_LIST:
                if match.startswith("#"):
                    continue
                if match.lower().rstrip("\n") in imp.lower():
                    if imp not in self.interesting_imports:
                        self.interesting_imports.append(imp)

    def __section_analysis(self):
        section_flags_name = {
            "exec": "IMAGE_SCN_CNT_CODE",
            "can_exec": "IMAGE_SCN_MEM_EXECUTE",
            "read": "IMAGE_SCN_MEM_READ",
            "write": "IMAGE_SCN_MEM_WRITE"
        }
        usual_sections_characteristic = {
            ".text": [section_flags_name["exec"], section_flags_name["can_exec"], section_flags_name["read"]],
            ".rdata": [section_flags_name["read"]],
            ".data": [section_flags_name["read"], section_flags_name["write"]],
            ".edata": [section_flags_name["read"]],
            ".idata": [section_flags_name["read"]],
            ".pdata": [section_flags_name["read"]],
            ".bss": [section_flags_name["read"]],
            ".rsrc": [section_flags_name["read"]],
            ".reloc": [section_flags_name["read"]]
        }
        for sect in self.pedata.sections:
            unusual_name = False
            unusual_permissions = False
            permissions = list()
            # (•_•)
            sect_name = sect.Name.decode().split("\x00", 1)[0]
            # if section name is unusual we want to know permissions
            if sect_name not in usual_sections_characteristic.keys():
                unusual_name = True
                unusual_permissions = True
                for perm, value in section_flags_name.items():
                    if getattr(sect, value):
                        permissions.append(perm)

            # if usual section name we want to know unusual permissions
            else:
                for perm, value in section_flags_name.items():
                    if getattr(sect, value) and value not in usual_sections_characteristic[sect_name]:
                        unusual_permissions = True
                        permissions.append(perm)
                    else:
                        if getattr(sect, value):
                            permissions.append(perm)

            # check if virtual size is larger than 170% of raw size -> packed?
            sect_size_diff = True if sect.Misc_VirtualSize > sect.SizeOfRawData * 1.7 else False

            sect_analysis = {
                "unusual_name": unusual_name,
                "unusual_permissions": unusual_permissions,
                "permissions": permissions,
                "raw_virtual_size_diff": sect_size_diff,
                "raw_size": hex(sect.SizeOfRawData),
                "virtual_size": hex(sect.Misc_VirtualSize),
                "entropy": sect.get_entropy() # if entropy > 7.4 == packed ? based on comments peutils
            }
            self.section_analysis.update({sect_name: sect_analysis})

    def __analyze(self):
        self.__get_imports_exports()
        self.__import_analysis()
        self.__section_analysis()
        # If .tls in section names we want to know
        self.tls = True if ".tls" in self.section_analysis.keys() else False
        self.probably_packed = peutils.is_probably_packed(self.pedata)


def check_right_pe(path: str) -> bool:
    header_data = open(path, "rb").read(2048)
    file_type = magic.from_buffer(header_data)
   # print(file_type)
    if "PE32" in file_type and ".Net assembly" not in file_type:
        return True
    return False


def check_mkdir(path: str) -> None:
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        os.mkdir(path)
    return


# Keeps updating at runtime, not a problem but annoyance
#def absolute_file_path(dir_path):
#    for dirpath, _, filenames in os.walk(dir_path):
#        for f in filenames:
#            yield os.path.abspath(os.path.join(dirpath, f))
def absolute_file_path(dir_path: str) -> list:
    flist = list()
    for root, dirs, files in os.walk(os.path.abspath(dir_path)):
        for file in files:
            flist.append(os.path.join(root, file))
    return flist


def chunk_reader(fobj, chunk_size=1024):
    """Generator that reads a file in chunks of bytes"""
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk


def get_hash(filename, hash=hashlib.sha1):
    hashobj = hash()
    file_obj = open(filename, "rb")

    for chunk in chunk_reader(file_obj):
        hashobj.update(chunk)
    hashed = hashobj.digest()

    file_obj.close()
    return hashed


# This is duplicate work, as the analysis also takes a hash, but it is for pool work
def remove_duplicate_files(path_list: list) -> list:
    hash_list = list()
    unique_list = list()
    for p in path_list:
        sha1 = get_hash(p)
        if sha1 not in hash_list:
            hash_list.append(sha1)
            unique_list.append(p)
    return unique_list


def bulk_analyze(dir_path: str) -> None:
    global WORK_DIR
    # Get absolute path for sample files
    sample_paths = absolute_file_path(dir_path)
    # if bulk analysis, change workdir to sample dir
    WORK_DIR = os.path.abspath(dir_path) + os.sep + WORK_DIR

    # create working dir
    check_mkdir(WORK_DIR)

    print("Removing duplicate files.")
    unique_files = remove_duplicate_files(sample_paths)

    # multiprocessing with pool
    pool = multiprocessing.Pool(NUMBERS_OF_CORES_TO_USE)
    result = pool.map(start_analysis_wrapper, unique_files)

    print("Done?")


def start_analysis_wrapper(sample: str) -> bool: # ret false nothing done, ret true done
    if check_right_pe(sample):
        print("Starting analyzing: " + sample)
        try:
            analysis = AnalyzeFile(sample)
            analysis.pprint()
            return True
        except AlreadyAnalyzed:
            return False
        except UnwantedPacker:
            return False
    else:
        print("[!] Sample is wrong type of file, no analysis on " + sample)
        return False


# Makes an arbitrarily nested list flat
def flatten_list(nested_list: list):
    nested_list = deepcopy(nested_list)
    while nested_list:
        sublist = nested_list.pop(0)

        if isinstance(sublist, list):
            nested_list = sublist + nested_list
        else:
            yield sublist


def main():
    desc = "Picky! Because there are always better things to look at!\nSupposed to be bulk based. Takes a file or dir."
    epilog = ""
    parser = argparse.ArgumentParser(
        description=desc, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("sample", type=str,
                        help="Path to file or folder with samples. If folder all files will be gathered, depth=1.")
    parser.add_argument("-p", "--dbgprint", action="store_true", help="Print debugging related information.")
    parser.add_argument("-m", "--multiprocess", type=int,
                        help="How many processes to use with bulk analysis. Default is 4.")
    #parser.add_argument("-h", "--help", action="store_true", help="Print help message and exit.")

    try:
        args = parser.parse_args()
    except:
        parser.print_usage()
        sys.exit(0)

    if args.dbgprint:
        logging.getLogger("picky").setLevel(logging.DEBUG)

    if args.multiprocess and args.multiprocess > 0:
        global NUMBERS_OF_CORES_TO_USE
        NUMBERS_OF_CORES_TO_USE = args.multiprocess

    if os.path.isdir(args.sample):
        bulk_analyze(args.sample)
        sys.exit(0)

    else:
        global WORK_DIR
        # Get absolute path for sample files
        sample_paths = str(os.path.abspath(args.sample))

        WORK_DIR = os.path.dirname(sample_paths) + os.sep + WORK_DIR

        # create working dir
        check_mkdir(WORK_DIR)
        start_analysis_wrapper(args.sample)
        sys.exit(0)


if __name__ == "__main__":
    main()
