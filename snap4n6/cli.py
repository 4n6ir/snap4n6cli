import argparse
import boto3
import hashlib
import io
import os
import sys
from tqdm import tqdm
from snap4n6 import __version__

s3_client = boto3.client('s3')

def getblocklist(bucket):
	blocks = []
	paginator = s3_client.get_paginator('list_objects_v2')
	response_iterator = paginator.paginate(Bucket = bucket)
	for page in response_iterator:
		for content in page['Contents']:
			blocks.append(content['Key'])
	return blocks

def getimagesize(bucket, snapid):
	try:
		response = s3_client.list_objects_v2(
			Bucket = bucket,
			MaxKeys = 1,
			Prefix = snapid+'/',
		)
		output = response['Contents'][0]['Key'].split('/')
		filevalue = output[1].split('_')
		return filevalue[3]
	except:
		print('Missing IAM Permissions on S3 Bucket --> '+bucket+'\n')
		print('  - s3:GetBucketLocation')
		print('  - s3:GetObject')
		print('  - s3:ListBucket\n')
		sys.exit(1)
		pass
	
def gets3bucket(region):
	try:
		ssm_client = boto3.client('ssm', region_name = region)
		response = ssm_client.get_parameter(Name = '/snap4n6/s3/bucket')
		return response['Parameter']['Value']
	except:
		print('Missing IAM Permission --> ssm:GetParameter for \'/snap4n6/s3/bucket\' in '+region)
		print('\n  or\n')
		print('Missing SSM Parameter --> is \'/snap4n6/s3/bucket\' deployed in '+region+'\n')
		sys.exit(1)
		pass
	
def getverification(snapid, sha256):
	sha256_hash = hashlib.sha256()
	with io.FileIO(snapid+'.tmp', 'rb') as f:
		for b in f:
			sha256_hash.update(b)
		f.close()
	if sha256_hash.hexdigest() != sha256:
		return 'ERROR'
	else:
		return 'SUCCESS'

def rebuild(region, snapid, ext4):
	bucket = gets3bucket(region)
	size = getimagesize(bucket, snapid)
	os.system('dd if=/dev/zero of='+snapid+'.dd bs=1 count=0 seek='+size+'G')
	if ext4 == True:
		os.system('echo y | mkfs.ext4 '+snapid+'.dd')
	log = open(snapid+'.log', 'w')
	blocks = getblocklist(bucket)
	with io.FileIO(snapid+'.dd', 'r+b') as image:
		for block in tqdm(blocks):
			output = block.split('/')
			value = output[1].split('_')
			s3_client.download_file(bucket, block, snapid+'.tmp')
			result = getverification(snapid, value[2])
			if result == 'ERROR':
				log.write(result+'\t'+output[1]+'\n')
			else:
				location = int(value[0]) * int(value[4])
				image.seek(location)
				with io.FileIO(snapid+'.tmp', 'rb') as block:
					for byte in block:
						image.write(byte)
				block.close()
	image.close()
	log.close()
	try:
		os.system('rm '+snapid+'.tmp')
	except:
		pass

def main():
	parser = argparse.ArgumentParser(description='Snap4n6 v'+__version__)
	required = parser.add_argument_group('Required')	
	required.add_argument('--region', type=str, help='us-east-2', required=True)
	required.add_argument('--snapid', type=str, help='snap-0f3e60199f11889da', required=True)
	optional = parser.add_argument_group('Optional')
	optional.add_argument('--ext4', action='store_true', help='Rebuild EXT4 File System')
	args = parser.parse_args()
	
	print('\nSnap4n6 v'+__version__+'\n')
	print('Region: \t'+args.region)
	print('Snapshot: \t'+args.snapid)
	print('Ext4 Fs: \t'+str(args.ext4)+'\n')

	rebuild(args.region, args.snapid, args.ext4)