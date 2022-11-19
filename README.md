# Snap4n6 CLI

Rebuild Elastic Block Storage (EBS) direct API blocks into a DD forensic image generated by Snap4n6 Serverless Imager.

### Permissions

- s3:GetBucketLocation
- s3:GetObject
- s3:ListBucket
- ssm:GetParameter

### Installation

```
pip install snap4n6
```

### Help

```
Snap4n6 v0.4.0

optional arguments:
  -h, --help       show this help message and exit

Required:
  --region REGION  us-east-2
  --snapid SNAPID  snap-0f3e60199f11889da

Optional:
  --ext4           Rebuild EXT4 File System
```

### Command

Microsoft Windows Snapshots contain the NTFS File System necessary to rebuild a forensic image.  

Linux Snapshots require the creation of Superblocks for the EXT4 File System using: ```mkfs.ext4```

```
snap4n6 --region us-east-2 --snapid snap-0f3e60199f11889da --ext4
```

### Output

```
Snap4n6 v0.4.0


Region:         us-east-2
Snapshot:       snap-0f3e60199f11889da
Ext4 Fs:        True

0+0 records in
0+0 records out
0 bytes (0 B) copied, 0.000209499 s, 0.0 kB/s
mke2fs 1.42.9 (28-Dec-2013)
snap-0f3e60199f11889da.dd is not a block special device.
Proceed anyway? (y,n) Discarding device blocks: done                            
Filesystem label=
OS type: Linux
Block size=4096 (log=2)
Fragment size=4096 (log=2)
Stride=0 blocks, Stripe width=0 blocks
65536 inodes, 262144 blocks
13107 blocks (5.00%) reserved for the super user
First data block=0
Maximum filesystem blocks=268435456
8 block groups
32768 blocks per group, 32768 fragments per group
8192 inodes per group
Superblock backups stored on blocks: 
        32768, 98304, 163840, 229376

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (8192 blocks): done
Writing superblocks and filesystem accounting information: done

  4%|██▌                       | 4/104 [00:05<02:07,  1.28s/it]
```

### Local Development

```
$ python setup.py install --user
```

### Alternatives

- aws-snap-io - https://github.com/forensicmatt/aws-snap-io
- coldsnap - https://github.com/awslabs/coldsnap
