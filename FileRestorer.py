# BandarChor FileRestorer v0.2.3 [2015-05-13]
import os, shutil, struct, sys, logging


### Set this to the suffix used on your files
BANDARCHOR_SUFFIX = '.id-1334663620_fudx@lycos.com'


class FileRestorer(object):
	""" Restores the file signatures in files encrypted by BandarChor cryptolocker malware.
		It does not overwrite the original file. The recovered file is prefixed with 'CORRUPT__'.
		It searches the given directory recursively for files with the given suffix.

		Explanation: The malware only encrypts part of a file, and the first 4 bytes specify
		the number of encrypted bytes. The encrypted part cannot be recovered without the key.
		FileRestorer erases the encrypted portion.
		Restoring the file signature can make recovery easier.
		The percentage of recovered data will also be calculated, identifying files most likely
		to have usable data.
		Files with no recoverable data will be skipped.
	"""
	_ZIP_BYTES = bytearray(b"\x50\x4B\x03\x04\x50\x4B\x05\x06")
	_OFFICE_BYTES = bytearray(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
	_JPG_BYTES = bytearray(b"\xFF\xD8\xFF\xE0")
	FILE_SIGNATURES = {
			'PDF': bytearray(b"\x25\x50\x44\x46\x2D\x31\x2E\x33\x0A\x25\xC4\xE5\xF2\xE5\xEB\xA7"),
			'XLS': _OFFICE_BYTES,
			'DOC': _OFFICE_BYTES,
			'PPT': _OFFICE_BYTES,
			'ZIP': _ZIP_BYTES,
			'XLSX': _ZIP_BYTES,
			'DOCX': _ZIP_BYTES,
			'PPTX': _ZIP_BYTES,
			'JPEG': _JPG_BYTES,
			'JPG': _JPG_BYTES,
			'TXT': bytearray(b"")
		  }
	FILL_BYTE = ord('#')

	def __init__(self, suffix):
		assert('.id-' in suffix)
		self.suffix = suffix

	def _regenerate_header(self, src, dest, filetype, max_file_size):
		logging.info("Processing {}".format(src))
		if filetype not in FileRestorer.FILE_SIGNATURES.keys():
			logging.info("Skipped (no registered file signature for file type {})".format(filetype))
			return False
		if os.path.isfile(dest):
			logging.info("Skipped (already patched)")
			return False

		file_size = os.path.getsize(src)
		if file_size > max_file_size:
			logging.info("Skipped (exceeds maximum specified size of {})".format(max_file_size))
			return False

		with open(src, 'rb') as f:
			bytes = f.read(4)
			enc_size = struct.unpack('<L', bytes)[0]

		if enc_size >= file_size-4:
			logging.info("Skipped (no recoverable data)")
			return False

		shutil.copyfile(src, dest)

		header = FileRestorer.FILE_SIGNATURES[filetype]
		header_size = len(header)
		n_fill_bytes = enc_size - header_size
		fill_bytes = bytearray([FileRestorer.FILL_BYTE for _ in range(n_fill_bytes)])

		with open(dest, 'r+b') as f:
			f.seek(0)
			f.write(header)
			f.write(fill_bytes)
			f.seek(-4, os.SEEK_END)		# the last 4 bytes in the locked file are the first 4 of the encrypted block
			f.truncate()

		percent_recovered = 100 - int(100.0 * enc_size / file_size)
		logging.info("SUCCESS: up to {}% file content recovered".format(percent_recovered))
		return True

	def _gen_save_filename(self, in_filename):
		ext_to_remove = self.suffix
		out_filename = in_filename.replace(ext_to_remove, '')
		out_filename = 'CORRUPT__' + out_filename
		return out_filename

	def start(self, target_dir='.', max_file_size=100000000):
		""" Starts the file recovery process, recursively scanning from target_dir.
		Args:
			target_dir: the directory to scan (default: current working directory)
			max_file_size: the maximum size in bytes of files to recover
		"""
		assert(self.suffix)

		logging.info("Recursively searching '{}' for files with filenames containing '{}'".format(target_dir, self.suffix))
		print('')

		attempted_recovery_count = 0
		recovery_count = 0
		for root, dirs, filenames in os.walk(target_dir):
			for filename in filenames:
				if not filename.endswith(self.suffix):
					continue
				attempted_recovery_count += 1
				in_file_path = os.path.join(root, filename)
				out_file_path = os.path.join(root, self._gen_save_filename(filename))
				filetype = os.path.splitext(out_file_path)[1].replace('.', '').upper()
				success = self._regenerate_header(in_file_path, out_file_path, filetype, max_file_size)
				recovery_count += 1 if success else 0
				print('')
		print('')
		logging.info("Recovered {} of {} files".format(recovery_count, attempted_recovery_count))



def main():
	set_up_loggers()

	target_dir = sys.argv[1] if len(sys.argv) == 2 else '.'

	restorer = FileRestorer(BANDARCHOR_SUFFIX)
	restorer.start(target_dir)




def set_up_loggers():
	root = logging.getLogger()
	root.setLevel(logging.INFO)
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.INFO)
	ch.setFormatter(logging.Formatter('%(message)s'))
	fh = logging.FileHandler('FileRestorer.log')
	fh.setLevel(logging.INFO)
	fh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
	root.addHandler(ch)
	root.addHandler(fh)

if __name__ == '__main__':
	main()
