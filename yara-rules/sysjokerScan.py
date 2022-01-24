#! /usr/bin/env python3

import argparse
import logging
from subprocess import PIPE, Popen


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog = "Sysjoker backdoor scan",
                                     description = "Sysjoker backdoor scan, for windows")
    parser.add_argument("--rule", required=True, help = "rule file")
    parser.add_argument("--dir", required=True, help = "this dir will scan")
    parser.add_argument("--error", required=False, type = int, choices = [0, 1], help = "print error info(0 disable, 1 enable)")
    args = parser.parse_args()
    try:
        if args.dir:
            if args.rule:
                cmd = f"yara32.exe -m -w -f -r {args.rule} {args.dir}"
            else:
                logging.WARNING("[-] not a rule file is set ... ")
                exit(1)
        else:
            logging.WARNING("[-] not a dir is set ... ")

        if cmd:
            proc = Popen(
                cmd,  # cmd特定的查询空间的命令
                stdin=None,  # 标准输入 键盘
                stdout=PIPE,  # -1 标准输出（演示器、终端) 保存到管道中以便进行操作
                stderr=PIPE,  # 标准错误，保存到管道
                shell=True)
            outinfo, errinfo = proc.communicate()
            outinfo = outinfo.decode('gbk')
            errinfo = errinfo.decode('gbk')

            print(outinfo)
            if args.error:
                print("----[ error msg ]----")
                print(errinfo)
            
    except Exception as e:
        print("[-] err", e)
