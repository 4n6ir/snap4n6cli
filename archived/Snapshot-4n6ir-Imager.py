import argparse
import base64
import boto3
import gzip
import hashlib
import io
import os
import shutil
from tqdm import tqdm
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
	
def budget(region,snapshot):
	count = 0
	status = 'START'
	ebs_role = boto3.client('ebs', region_name=region)
	while(status):
		if status == 'START':
			response = ebs_role.list_snapshot_blocks(SnapshotId=snapshot)
			for block in tqdm(response['Blocks']):
				count = count + 1
			try:
				status = response['NextToken']
			except:
				status = ''
				continue
		else:
			response = ebs_role.list_snapshot_blocks(SnapshotId=snapshot,NextToken=status)
			for block in tqdm(response['Blocks']):
				count = count + 1
			try:
				status = response['NextToken']
			except:
				status = ''
				continue
	
	dlsize = (count * response['BlockSize']) / (1024 * 1024 * 1024)
	print('\nAPI Quantity: \t'+str(count))
	print('Download Size: \t'+str(round(dlsize,2))+' GB')
	print('Volume Size: \t'+str(response['VolumeSize'])+' GB')

def changed(region,snapshot,base):
	if not os.path.exists(snapshot):
		os.makedirs(snapshot)
	status = 'START'
	ebs_role = boto3.client('ebs', region_name=region)
	while(status):
		if status == 'START':
			response = ebs_role.list_changed_blocks(FirstSnapshotId=base,SecondSnapshotId=snapshot)
			for block in tqdm(response['ChangedBlocks']):
				download = ebs_role.get_snapshot_block(SnapshotId=snapshot,
													 BlockIndex=block['BlockIndex'],
													 BlockToken=block['SecondBlockToken'])
				sha256_hash = hashlib.sha256()
				with io.FileIO(snapshot+'.tmp', 'wb') as f:
					for b in download['BlockData']:
						sha256_hash.update(b)
						f.write(b)
				f.close()
				fname = str(block['BlockIndex']).zfill(10)+'_'+snapshot+'_'+sha256_hash.hexdigest()+'_'+str(response['VolumeSize'])+'_'+str(response['BlockSize'])
				shutil.move(snapshot+'.tmp',snapshot+'/'+fname)
			try:
				status = response['NextToken']
			except:
				status = ''
				continue
		else:
			response = ebs_role.list_changed_blocks(FirstSnapshotId=base,SecondSnapshotId=snapshot,NextToken=status)
			for block in tqdm(response['ChangedBlocks']):
				download = ebs_role.get_snapshot_block(SnapshotId=snapshot,
													 BlockIndex=block['BlockIndex'],
													 BlockToken=block['SecondBlockToken'])
				sha256_hash = hashlib.sha256()
				with io.FileIO(snapshot+'.tmp', 'wb') as f:
					for b in download['BlockData']:
						sha256_hash.update(b)
						f.write(b)
				f.close()
				fname = str(block['BlockIndex']).zfill(10)+'_'+snapshot+'_'+sha256_hash.hexdigest()+'_'+str(response['VolumeSize'])+'_'+str(response['BlockSize'])
				shutil.move(snapshot+'.tmp',snapshot+'/'+fname)
			try:
				status = response['NextToken']
			except:
				status = ''
				continue

def compare(region,snapshot,base):
	count = 0
	status = 'START'
	ebs_role = boto3.client('ebs', region_name=region)
	f = open(snapshot+'_changelog.txt','w')
	f.write('blockindex|offset|length\n')
	while(status):
		if status == 'START':
			response = ebs_role.list_changed_blocks(FirstSnapshotId=base,SecondSnapshotId=snapshot)
			for block in tqdm(response['ChangedBlocks']):
				offset = block['BlockIndex'] * response['BlockSize']
				f.write(str(block['BlockIndex'])+'|'+str(offset)+'|'+str(response['BlockSize'])+'\n')
				count = count + 1
			try:
				status = response['NextToken']
			except:
				status = ''
				continue
		else:
			response = ebs_role.list_changed_blocks(FirstSnapshotId=base,SecondSnapshotId=snapshot,NextToken=status)
			for block in tqdm(response['ChangedBlocks']):
				offset = block['BlockIndex'] * response['BlockSize']
				f.write(str(block['BlockIndex'])+'|'+str(offset)+'|'+str(response['BlockSize'])+'\n')				
				count = count + 1
			try:
				status = response['NextToken']
			except:
				status = ''
				continue
	f.close()

	dlsize = (count * response['BlockSize']) / (1024 * 1024 * 1024)
	print('\nAPI Quantity: \t'+str(count))
	print('Download Size: \t'+str(round(dlsize,2))+' GB')

def compress(snapshot):
	filelist = os.listdir(snapshot)
	if not os.path.exists(snapshot+'_compressed'):
		os.makedirs(snapshot+'_compressed')
	for item in tqdm(filelist):
		with io.FileIO(snapshot+'/'+item, 'rb') as r:
			with gzip.open(snapshot+'_compressed/'+item+'.gz','wb') as w:
				for b in r:
					w.write(b)
			w.close()
		r.close()

def createkey(password,salt):
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
					 length=32,
					 salt=salt.encode(),
					 iterations=100000,
					 backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	f = Fernet(key)
	return f

def decrypt(snapshot,password,salt):
	filelist = os.listdir(snapshot+'_encrypted')
	if not os.path.exists(snapshot+'_compressed'):
		os.makedirs(snapshot+'_compressed')
	f = createkey(password,salt)
	for item in tqdm(filelist):
		with io.FileIO(snapshot+'_encrypted/'+item,'rb') as r:
			data = r.read()
		r.close()
		decrypted = f.decrypt(data)
		with io.FileIO(snapshot+'_compressed/'+item[:-10],'wb') as w:
			w.write(decrypted)
		w.close()

def encrypt(snapshot,password,salt):
	filelist = os.listdir(snapshot+'_compressed')
	if not os.path.exists(snapshot+'_encrypted'):
		os.makedirs(snapshot+'_encrypted')
	f = createkey(password,salt)
	for item in tqdm(filelist):
		with io.FileIO(snapshot+'_compressed/'+item,'rb') as r:
			data = r.read()
		r.close()
		encrypted = f.encrypt(data)
		with io.FileIO(snapshot+'_encrypted/'+item+'.encrypted','wb') as w:
			w.write(encrypted)
		w.close()

def image(region,snapshot):
	if not os.path.exists(snapshot):
		os.makedirs(snapshot)
	status = 'START'
	ebs_role = boto3.client('ebs', region_name=region)
	while(status):
		if status == 'START':
			response = ebs_role.list_snapshot_blocks(SnapshotId=snapshot)
			for block in tqdm(response['Blocks']):
				download = ebs_role.get_snapshot_block(SnapshotId=snapshot,
													 BlockIndex=block['BlockIndex'],
													 BlockToken=block['BlockToken'])
				sha256_hash = hashlib.sha256()
				with io.FileIO(snapshot+'.tmp', 'wb') as f:
					for b in download['BlockData']:
						sha256_hash.update(b)
						f.write(b)
				f.close()
				fname = str(block['BlockIndex']).zfill(10)+'_'+snapshot+'_'+sha256_hash.hexdigest()+'_'+str(response['VolumeSize'])+'_'+str(response['BlockSize'])
				shutil.move(snapshot+'.tmp',snapshot+'/'+fname)
			try:
				status = response['NextToken']
			except:
				status = ''
				continue
		else:
			response = ebs_role.list_snapshot_blocks(SnapshotId=snapshot,NextToken=status)
			for block in tqdm(response['Blocks']):
				download = ebs_role.get_snapshot_block(SnapshotId=snapshot,
													 BlockIndex=block['BlockIndex'],
													 BlockToken=block['BlockToken'])
				sha256_hash = hashlib.sha256()
				with io.FileIO(snapshot+'.tmp', 'wb') as f:
					for b in download['BlockData']:
						sha256_hash.update(b)
						f.write(b)
				f.close()
				fname = str(block['BlockIndex']).zfill(10)+'_'+snapshot+'_'+sha256_hash.hexdigest()+'_'+str(response['VolumeSize'])+'_'+str(response['BlockSize'])
				shutil.move(snapshot+'.tmp',snapshot+'/'+fname)							
			try:
				status = response['NextToken']
			except:
				status = ''
				continue

def ext4(snapshot):
	filelist = os.listdir(snapshot)
	for item in filelist:
		filevalue = item.split('_')
		os.system('dd if=/dev/zero of='+snapshot+'.dd bs=1 count=0 seek='+filevalue[3]+'G')
		os.system('mkfs.ext4 '+snapshot+'.dd')
		break
	with io.FileIO(snapshot+'.dd', 'r+b') as f:
		for item in tqdm(filelist):
			filevalue = item.split('_')
			location = int(filevalue[0]) * int(filevalue[4])
			f.seek(location)
			with io.FileIO(snapshot+'/'+item, 'rb') as t:
				for b in t:
					f.write(b)
			t.close()
	f.close()

def ntfs(snapshot):
	filelist = os.listdir(snapshot)
	for item in filelist:
		filevalue = item.split('_')
		os.system('dd if=/dev/zero of='+snapshot+'.dd bs=1 count=0 seek='+filevalue[3]+'G')
		break
	with io.FileIO(snapshot+'.dd', 'r+b') as f:
		for item in tqdm(filelist):
			filevalue = item.split('_')
			location = int(filevalue[0]) * int(filevalue[4])
			f.seek(location)
			with io.FileIO(snapshot+'/'+item, 'rb') as t:
				for b in t:
					f.write(b)
			t.close()
	f.close()

def single(region,snapshot,block):
	if not os.path.exists(snapshot):
		os.makedirs(snapshot)
	ebs_role = boto3.client('ebs', region_name=region)
	response = ebs_role.list_snapshot_blocks(SnapshotId=snapshot,
    									   MaxResults=100,
    									   StartingBlockIndex=int(block))
	for block in response['Blocks']:
		download = ebs_role.get_snapshot_block(SnapshotId=snapshot,
											 BlockIndex=block['BlockIndex'],
											 BlockToken=block['BlockToken'])
		sha256_hash = hashlib.sha256()
		with io.FileIO(snapshot+'.tmp', 'wb') as f:
			for b in download['BlockData']:
				sha256_hash.update(b)
				f.write(b)
		f.close()
		fname = str(block['BlockIndex']).zfill(10)+'_'+snapshot+'_'+sha256_hash.hexdigest()+'_'+str(response['VolumeSize'])+'_'+str(response['BlockSize'])
		shutil.move(snapshot+'.tmp',snapshot+'/'+fname)
		print('Completed!')
		break

def uncompress(snapshot):
	filelist = os.listdir(snapshot+'_compressed')
	if not os.path.exists(snapshot):
		os.makedirs(snapshot)
	for item in tqdm(filelist):
		with gzip.open(snapshot+'_compressed/'+item,'rb') as r:
			with io.FileIO(snapshot+'/'+item[:-3], 'wb') as w:
				for b in r:
					w.write(b)		
			w.close()
		r.close()

def verify(snapshot):
	filelist = os.listdir(snapshot)
	for item in tqdm(filelist):
		sha256 = item.split('_')
		sha256_hash = hashlib.sha256()
		with io.FileIO(snapshot+'/'+item, 'rb') as f:
			for b in f:
				sha256_hash.update(b)
		f.close()
		if sha256_hash.hexdigest() != sha256[2]:
			print('\nERROR: '+item+'\n')

def main():
	parser = argparse.ArgumentParser(description="Snapshot 4n6ir Imager v0.3.1")
	required = parser.add_argument_group('Required')	
	required.add_argument("--region", type=str, help="us-east-2", required=True)
	required.add_argument("--snapshot", type=str, help="snap-056e0b1bd07ad91b2", required=True)
	voluntary = parser.add_argument_group('Voluntary')
	voluntary.add_argument("--base", type=str, help="Base Build Snapshot")
	voluntary.add_argument("--block", type=str, help="Block Index Number")
	voluntary.add_argument("--budget", action="store_true", help="API Quantity & Download Size")
	voluntary.add_argument("--changed", action="store_true", help="Image Changed EBS Snapshot Blocks")
	voluntary.add_argument("--compare", action="store_true", help="Snapshot Comparison")
	voluntary.add_argument("--compress", action="store_true", help="Compress EBS Snapshot Blocks")
	voluntary.add_argument("--decrypt", action="store_true", help="Decrypt Compressed EBS Snapshot Blocks")
	voluntary.add_argument("--encrypt", action="store_true", help="Encrypt Compressed EBS Snapshot Blocks")
	voluntary.add_argument("--ext4", action="store_true", help="Rebuild EXT4 File System")
	voluntary.add_argument("--image", action="store_true", help="Image EBS Snapshot Blocks")
	voluntary.add_argument("--ntfs", action="store_true", help="Rebuild NTFS File System")
	voluntary.add_argument("--password", type=str, help="Encryption & Decryption Password")
	voluntary.add_argument("--salt", type=str, help="Encryption & Decryption Salt")
	voluntary.add_argument("--single", action="store_true", help="Image Single EBS Snapshot Block")
	voluntary.add_argument("--uncompress", action="store_true", help="Uncompress EBS Snapshot Blocks")
	voluntary.add_argument("--verify", action="store_true", help="Verify EBS Snapshot Blocks")
	args = parser.parse_args()
	
	print('Snapshot 4n6ir Imager v0.3.1\n')
	print('Region: \t'+args.region)
	print('Snapshot: \t'+args.snapshot+'\n')
	
	### BUDGET ###
	if(args.budget == True):
		budget(args.region,args.snapshot)
	### CHANGED ###
	elif(args.changed == True):
		if(args.base and args.changed):
			changed(args.region,args.snapshot,args.base)
		else:
			print('-- Base Required --')
	### COMPARE ###
	elif(args.compare == True):
		if(args.base and args.compare):
			compare(args.region,args.snapshot,args.base)
		else:
			print('-- Base Required --')
	### COMPRESS ###
	elif(args.compress == True):
		compress(args.snapshot)
	### DECRYPT ###
	elif(args.decrypt == True):
		if(args.password and args.salt):
			decrypt(args.snapshot,args.password,args.salt)
		else:
			print('-- Password & Salt Required --')
	### ENCRYPT ###
	elif(args.encrypt == True):
		if(args.password and args.salt):
			encrypt(args.snapshot,args.password,args.salt)
		else:
			print('-- Password & Salt Required --')
	### IMAGE ###
	elif(args.image == True):
		image(args.region,args.snapshot)
	### EXT4 ###
	elif(args.ext4 == True):
		ext4(args.snapshot)
	### NTFS ###
	elif(args.ntfs == True):
		ntfs(args.snapshot)
	### SINGLE ###
	elif(args.single == True):
		if(args.single and args.block):
			single(args.region,args.snapshot,args.block)
		else:
			print('-- Block Index Number Required --')
	### UNCOMPRESS ###
	elif(args.uncompress == True):
		uncompress(args.snapshot)
	### VERIFY ###
	elif(args.verify == True):
		verify(args.snapshot)		
	### NO OPTIONS ###
	else:
		print('-- No Voluntary Options --')
	
if __name__ == "__main__":
	main()
