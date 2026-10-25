#!/usr/bin/env python3
"""Read-only, hardlink-aware candidates. Never delete, archive or inspect secrets."""
import argparse
from collections import defaultdict
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from ueba_research_artifacts import private_directory,commit

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
root=private_directory(a.output.resolve());runtime=root.parent
names=['hybrid-strict-source-20261004-pdSIQYiW','hybrid-strict-source-20261013-parallel-v2',
       'hybrid-strict-source-20261013-parallel-resume-154','hybrid-strict-source-20261013-parallel-bagl17my',
       'hybrid-strict-source-20261013-parallel-xkxki6a_']
rows=[]
for name in names:
    directory=runtime/name
    if not directory.is_dir() or directory.is_symlink():continue
    groups={};counts=defaultdict(int);files=0;symlinks=0
    for current,dirs,entries in os.walk(directory,followlinks=False):
        dirs[:]=[d for d in dirs if not (Path(current)/d).is_symlink()]
        for entry in entries:
            st=(Path(current)/entry).lstat()
            if stat.S_ISLNK(st.st_mode):symlinks+=1;continue
            if not stat.S_ISREG(st.st_mode):continue
            key=(st.st_dev,st.st_ino);groups[key]=(st.st_nlink,st.st_blocks*512);counts[key]+=1;files+=1
    exclusive=sum(size for inode,(links,size) in groups.items() if counts[inode]==links)
    rows.append({'directory':str(directory),'files':files,'symlinks_excluded':symlinks,
        'physical_bytes_including_shared_inodes':sum(size for _,size in groups.values()),
        'bytes_unlinked_only_if_all_links_inside_candidate':exclusive,
        'shared_inode_bytes_not_promised_reclaimed':sum(size for inode,(links,size) in groups.items() if counts[inode]<links),
        'decision':'REVIEW_ONLY_NOT_AUTHORIZED_FOR_DELETE','archive_dependency_and_restore_verification_required':True})
lsblk=json.loads(subprocess.check_output(['lsblk','--json','-b','-o','NAME,SIZE,FSTYPE,MOUNTPOINTS,RM'],text=True))
removable=[]
def scan(items):
    for value in items:
        if value.get('rm') and value.get('mountpoints') and any(value['mountpoints']):
            removable.append({k:value.get(k) for k in ('name','size','fstype','mountpoints')})
        scan(value.get('children',[]))
scan(lsblk['blockdevices'])
report={'status':'READONLY_STORAGE_CANDIDATES_INVENTORIED','checked_at_utc':datetime.now(timezone.utc).isoformat(),
    'ssd_free_bytes':shutil.disk_usage(root).free,'reserve_bytes':5000000000,'candidates':rows,
    'usb_mounted_candidates':removable,'usb_state':'NOT_ATTACHED_OR_NOT_MOUNTED' if not removable else 'INSPECTION_REQUIRED_NO_WRITES',
    'protected':['CanonicalR2 with models,source,score/parallel cache pairs,mappings,journals and frozen code',
                 'All current postlogin parents/checkpoints','Private backups,mail/env credentials and website DB volumes'],
    'already_performed_cache_cleanup':{'command':'docker builder prune --force --filter until=168h','reported_reclaimed_bytes_approx':6905000000,'images_and_volumes_deleted':False},
    'candidate_sizes_not_additive_due_to_cross_hardlinks':True,'new_deletions':0,'new_fits':0,'quota_policy':'NOT_USED',
    'next_action':'Provide exact archive/delete allowlist for review after dependency checks and USB readback; keep all listed research candidates intact now.'}
commit(root,report,phase='storage-inventory-v1')
print(json.dumps({'status':report['status'],'ssd_free_bytes':report['ssd_free_bytes'],'usb_state':report['usb_state'],
    'candidate_count':len(rows),'new_deletions':0,'exclusive_candidate_bytes_upper_before_approval':sum(r['bytes_unlinked_only_if_all_links_inside_candidate'] for r in rows)}))
