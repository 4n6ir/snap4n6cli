import argparse
import boto3
import sys
from snap4n6 import __version__

def getimagesize(bucket, snapid):
	try:
		s3_client = boto3.client('s3')
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

def rebuild(region, snapid, ext4, status):
	bucket = gets3bucket(region)
	imagesize = getimagesize(bucket, snapid)

def main():
	parser = argparse.ArgumentParser(description='Snap4n6 v'+__version__)
	required = parser.add_argument_group('Required')	
	required.add_argument('--region', type=str, help='us-east-2', required=True)
	required.add_argument('--snapid', type=str, help='snap-0f3e60199f11889da', required=True)
	optional = parser.add_argument_group('Optional')
	optional.add_argument('--ext4', action='store_true', help='Rebuild EXT4 File System')
	optional.add_argument('--status', action='store_true', help='Status of Image Rebuild')
	args = parser.parse_args()
	
	print('\nSnap4n6 v'+__version__+'\n')
	print('Region: \t'+args.region)
	print('Snapshot: \t'+args.snapid)
	print('Ext4 Fs: \t'+str(args.ext4))
	print('Status: \t'+str(args.status)+'\n')

	rebuild(args.region, args.snapid, args.ext4, args.status)