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
    ap.add_argument('--arch', default='x86_64', help='The architecture for which driver must be built.')
    ap.add_argument('--rebuild', action='store_true', help='Rebuild all drivers, including the ones already present on S3')
    ap.add_argument('--version', default='', help='Specific version to be built of the driver in the config_dir.')
    ap.add_argument('--dry-run', action='store_true', help='Dry run the build script.')
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

    if args.version is None:
        dri_dirs = [x for x in config_dir.iterdir() if x.is_dir()]
    else:
        version_dir = Path(args.config_dir, args.version)
        if version_dir.is_dir():
            dri_dirs = [version_dir]
        else:
            print(f"[-] {args.version} configs not found in {config_dir}")
            return 1

    for dri_dir in dri_dirs:
        config_dirs = [x for x in dri_dir.iterdir() if x.is_dir()]
        for config_dir in config_dirs:
            # if arch is not dediced implicitly, then it must be equal to the
            # config directory name
            arch = config_dir.name

            # skip this config if the arch is not the one we're building for
            if arch != args.arch:
                continue

            driverversion = dri_dir.name
            print(f"[*] loading drivers from driver version directory {driverversion} for arch {arch}")
            files = list(config_dir.glob("*.yaml"))
            print(f"[*] found {len(files)} files")
            if args.dry_run:
                print(f"[!] Running a dry run")

            already_build_list = []
            if not args.rebuild:
                prefix = f"{s3_prefix}/{driverversion}/{arch}/"
                paginator = s3.get_paginator('list_objects_v2')
                pages = paginator.paginate(Bucket=s3_bucket, Prefix=prefix, Delimiter="/")

                # Prefetch all driver already compiled
                already_build_list = [os.path.basename(obj['Key']) for page in pages for obj in page['Contents']]

                # Get the basename then remove the `scap_` prefix and `.ko` or `.o` extension
                # so we end up with the exact name of the config file
                exclude_list = ['.'.join(x[5:].split('.')[:-1]) for x in already_build_list]

                # Exclude only if both kmod and bpf driver are not built
                exclude_list = set([i for i in exclude_list if exclude_list.count(i)>1])

                # First remove the `.yaml` extension then filter the original file list
                files = [x for x in files if os.path.basename(x)[:-5] not in exclude_list]

            if not args.rebuild:
                prefix = f"{s3_prefix}/{driverversion}/{arch}/"
                paginator = s3.get_paginator('list_objects_v2')
                pages = paginator.paginate(Bucket=s3_bucket, Prefix=prefix, Delimiter="/")

                # Prefetch all driver already compiled
                exclude_list = [obj['Key'] for page in pages for obj in page['Contents']]

                # Get the basename then remove the `scap_` prefix and `.ko` or `.o` extension
                # so we end up with the exact name of the config file
                exclude_list = ['.'.join(os.path.basename(x)[5:].split('.')[:-1]) for x in exclude_list]

                # Exclude only if both kmod and bpf driver are not built
                exclude_list = set([i for i in exclude_list if exclude_list.count(i)>1])

                # First remove the `.yaml` extension then filter the original file list
                files = [x for x in files if os.path.basename(x)[:-5] not in exclude_list]


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
                    module_s3key = f"{s3_prefix}/{driverversion}/{arch}/{module_basename}"

                probe_s3key = None
                if probe_output is not None:
                    probe_basename = os.path.basename(probe_output)
                    probe_s3key = f"{s3_prefix}/{driverversion}/{arch}/{probe_basename}"

                if s3:
                    need_module = (module_output is not None) and (module_basename not in already_build_list)
                    need_probe  = (probe_output  is not None) and (probe_basename  not in already_build_list)
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

                if args.dry_run:
                    continue

                # note: we don't need to pass the target architecture to
                # driverkit, because we are assuming that the architecture is
                # specified in the YAML config files themselves.
                # The only exceptions could be old driver version that don't
                # support the multi-arch directory split, for which driverkit
                # fallsback to x86_64 anyway
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

                    if probe_output is not None and os.path.isfile(probe_output):
                        with open(probe_output, 'rb') as fp:
                            s3.upload_fileobj(fp, s3_bucket, probe_s3key, ExtraArgs={'ACL':'public-read'})
                        delete_file(probe_output)

            print(f"[*] Build {driverversion} complete. {success_count}/{count} built, {fail_count}/{count} failed, {skip_count}/{count} already built.")

    return 0

if __name__ == '__main__':
    sys.exit(main())
