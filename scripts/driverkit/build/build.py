#!/usr/bin/env python3

import sys
import os
import yaml
import boto3
import shutil
import argparse
import subprocess
from pathlib import Path
from botocore.errorfactory import ClientError

def driverkit_build(driverkit: str, config_file: Path, driverversion: str, devicename: str, drivername: str) -> bool:
    args = [driverkit, 'docker',
            '-c', str(config_file.resolve()),
            '--driverversion', driverversion,
            '--moduledevicename', devicename,
            '--moduledrivername', drivername,
            '--timeout', '1000']
    print('[*] {}'.format(' '.join(args)))
    status = subprocess.run(args)

    return status.returncode == 0

def s3_exists(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError:
        # Not found
        return False

    return True

def delete_file(filename: str):
    try:
        os.remove(filename)
    except OSError:
        pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('config_dir', help='The directory containing driverkit config files, organized as <driver_version>/<configN>.yaml')
    ap.add_argument('--driverkit', help='Path to the driverkit binary to use')
    ap.add_argument('--s3-bucket', help='The S3 bucket name')
    ap.add_argument('--s3-prefix', help='S3 key prefix')
    ap.add_argument('--moduledrivername', default='scap', help='The module driver name')
    ap.add_argument('--moduledevicename', default='scap', help='The module device name')
    ap.add_argument('--rebuild', action='store_true', help='Rebuild all drivers, including the ones already present on S3')
    args = ap.parse_args()

    if args.rebuild:
        print(f"[*] A full rebuild has been requested. This may take a while ...")

    config_dir = Path(args.config_dir)
    if not config_dir.exists():
        print(f"[-] config directory does not exist: {config_dir}")
        return 1

    driverkit = shutil.which('driverkit')
    if args.driverkit is not None:
        driverkit = args.driverkit

    if driverkit is None:
        print(f"[-] driverkit not found. Select the driverkit binary with --driverkit")
        return 1

    if not os.path.exists(driverkit):
        print(f"[-] driverkit binary {driverkit} does not exist")
        return 1

    s3 = None
    s3_bucket = None
    s3_prefix = None
    if args.s3_bucket is not None and args.s3_prefix is not None:
        s3 = boto3.client('s3')
        s3_bucket = args.s3_bucket
        s3_prefix = args.s3_prefix.lstrip('/')

    dri_dirs = [x for x in config_dir.iterdir() if x.is_dir()]
    for dri_dir in dri_dirs:
        driverversion = dri_dir.name
        print(f"[*] loading drivers from driver version directory {driverversion}")
        files = list(dri_dir.glob("*.yaml"))
        print(f"[*] found {len(files)} files")

        count = 0
        success_count = 0
        fail_count = 0
        skip_count = 0
        for config_file in files:
            count += 1
            print('[*] [{:03d}/{:03d}] {}'.format(count, len(files), config_file.name))

            with open(config_file) as fp:
                conf = yaml.safe_load(fp)

            module_output = conf.get('output', {}).get('module')
            probe_output = conf.get('output', {}).get('probe')
            
            module_s3key = None
            if module_output is not None:
                module_basename = os.path.basename(module_output)
                module_s3key = f"{s3_prefix}/{driverversion}/{module_basename}"

            probe_s3key = None
            if probe_output is not None:
                probe_basename = os.path.basename(probe_output)
                probe_s3key = f"{s3_prefix}/{driverversion}/{probe_basename}"

            if s3:
                need_module = (module_output is not None) and (args.rebuild or not s3_exists(s3, s3_bucket, module_s3key))
                need_probe = (probe_output is not None) and (args.rebuild or not s3_exists(s3, s3_bucket, probe_s3key))
            else:
                need_module = (module_output is not None) and (args.rebuild or not os.path.exists(module_output))
                need_probe = (probe_output is not None) and (args.rebuild or not os.path.exists(probe_output))

            need_build = need_module or need_probe
            if not need_build:
                skip_count += 1
                print('[*] {} already built'.format(config_file))
                continue

            # Make sure the output directory exists or driverkit will output "open: no such file or directory"
            if module_output is not None:
                Path(module_output).parent.mkdir(parents=True, exist_ok=True)
            if probe_output is not None:
                Path(probe_output).parent.mkdir(parents=True, exist_ok=True)

            success = driverkit_build(driverkit, config_file, driverversion, args.moduledevicename, args.moduledrivername)
            if success:
                print(f"[+] Build completed {config_file}")
                success_count += 1
            else:
                print(f"[-] Build failed {config_file}")
                fail_count += 1
                continue

            # upload to s3 and remove
            if s3:
                print(f"[*] Attempting upload to s3 bucket {s3_bucket} with module key {module_s3key}")
                if module_output is not None:
                    with open(module_output, 'rb') as fp:
                        s3.upload_fileobj(fp, s3_bucket, module_s3key, ExtraArgs={'ACL':'public-read'})
                    delete_file(module_output)

                if probe_output is not None:
                    with open(probe_output, 'rb') as fp:
                        s3.upload_fileobj(fp, s3_bucket, probe_s3key, ExtraArgs={'ACL':'public-read'})
                    delete_file(probe_output)

        print(f"[*] Build {driverversion} complete. {success_count}/{count} built, {fail_count}/{count} failed, {skip_count}/{count} already built.")

    return 0

if __name__ == '__main__':
    sys.exit(main())
