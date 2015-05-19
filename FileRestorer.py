# BandarChor FileRestorer v0.2.5 [2015-05-19]
import os, shutil, struct, sys, logging, re

# Files with the following extensions are targeted by BandarChor:
# .113, .1cd, .3gp, .73b, .a3d, .abf, .abk, .accdb, .arj, .as4, .asm, .asvx, .ate, .avi, .bac, .bak, .bck, .bkf, .cdr, .cer, .cpt, .csv, .db3, .dbf, .doc, .docx, .dwg, .erf, .fbf, .fbk, .fbw, .fbx, .fdb, .gbk, .gho, .gzip, .iv2i, .jpeg, .jpg, .key, .keystore, .ldf, .m2v, .m3d, .max, .mdb, .mkv, .mov, .mpeg, .nbd, .nrw, .nx1, .odb, .odc, .odp, .ods, .odt, .old, .orf, .p12, .pdf, .pef, .ppsx, .ppt, .pptm, .pptx, .pst, .ptx, .pwm, .pz3, .qic, .r3d, .rar, .raw, .rtf, .rwl, .rx2, .sbs, .sldasm, .sldprt, .sn1, .sna, .spf, .sr2, .srf, .srw, .tbl, .tib, .tis, .txt, .wab, .wps, .x3f, .xls, .xlsb, .xlsk, .xlsm, .xlsx, .zip
# Only a fraction of the file signatures for the associated types are included
# You should manually add any additional signatures


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

	BANDARCHOR_SUFFIX_REGEX = r"\.id-\d{10}_((fudx?)|(europay))@((lycos)|(india))\.com$"

	_ZIP_BYTES = bytearray(b"\x50\x4B\x03\x04\x50\x4B\x05\x06")
	_OFFICE_BYTES = bytearray(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
	_JPG_BYTES = bytearray(b"\xFF\xD8\xFF\xE0")
	_NO_BYTES = bytearray(b"")
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
			'TXT': _NO_BYTES
	        # ADD MORE FILE SIGNATURES HERE
		  }
	FILL_BYTE = ord('#')

	def __init__(self, verbose=True):
		self.verbose = verbose
		self.pattern = FileRestorer.BANDARCHOR_SUFFIX_REGEX
		assert('.id-' in self.pattern)

	def _regenerate_header(self, src, dest, filetype, max_file_size):
		if filetype not in self.target_types:
			if self.verbose:
				logging.info("-- {}".format(src))
				logging.info("Skipped ({} not an available target file type)".format(filetype))
			return False
		if os.path.isfile(dest):
			if self.verbose:
				logging.info("-- {}".format(src))
				logging.info("Skipped (already patched)")
			return False

		logging.info("-- {}".format(src))

		file_size = os.path.getsize(src)
		if file_size > max_file_size:
			logging.info("Skipped (exceeds maximum specified size of {})".format(max_file_size))
			return False

		with open(src, 'rb') as f:
			bytes = f.read(4)
			enc_size = struct.unpack('<L', bytes)[0]

		if enc_size >= file_size-4:
			logging.info("Failed: no recoverable data")
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

		logging.info("SUCCESS: {}% of uncorrupted file content ({} of {} bytes)".format(percent_recovered, enc_size, file_size-4))
		return True

	def _gen_save_filename(self, in_filename, ext_to_remove):
		out_filename = in_filename.replace(ext_to_remove, '')
		out_filename = 'CORRUPT__' + out_filename
		return out_filename

	def start(self, target_dir='.', target_types=None, max_file_size=100000000):
		""" Starts the file recovery process, recursively scanning from target_dir.
		Args:
			target_dir: the directory to scan (default: current working directory)
			target_types: list of file types to target (default: None [includes all])
			max_file_size: the maximum size in bytes of files to recover
		"""
		assert(self.pattern)

		self._set_target_file_types(target_types)

		logging.info("Recursively searching '{}' for files with filenames matching '{}'".format(target_dir, self.pattern))
		logging.info("Targeting {} of {} known signatures: {}".format(
				len(self.target_types), len(FileRestorer.FILE_SIGNATURES), ' '.join(self.target_types)))
		print('')

		attempted_recovery_count = 0
		recovery_count = 0
		for root, dirs, filenames in os.walk(target_dir):
			for filename in filenames:
				if not self._is_encrypted_file(filename):
					continue
				ext_to_remove = self._get_encrypted_file_suffix(filename)

				attempted_recovery_count += 1
				in_file_path = os.path.join(root, filename)
				out_file_path = os.path.join(root, self._gen_save_filename(filename, ext_to_remove))
				filetype = os.path.splitext(out_file_path)[1].replace('.', '').upper()
				success = self._regenerate_header(in_file_path, out_file_path, filetype, max_file_size)
				recovery_count += 1 if success else 0
				if self.verbose: print('')
		print('')
		logging.info("Recovered {} of {} files".format(recovery_count, attempted_recovery_count))

	def _set_target_file_types(self, target_types):
		avail_types = FileRestorer.FILE_SIGNATURES.keys()
		if not target_types:
			self.target_types = avail_types
			return

		self.target_types = [ext.upper() for ext in target_types if ext.upper() in avail_types]


	def _is_encrypted_file(self, filename):
		match = re.search(self.pattern, filename)
		return match != None

	def _get_encrypted_file_suffix(self, filename):
		suffix = re.search(self.pattern, filename).group(0)
		return suffix


def main():
	set_up_loggers('FileRestorer.log')

	target_dir = sys.argv[1] if len(sys.argv) == 2 else '.'

	restorer = FileRestorer(verbose=False)
	# restorer.start(target_dir, ['pdf', 'xls'])
	restorer.start(target_dir,)


def set_up_loggers(log_filename='FileRestorer.log'):
	root = logging.getLogger()
	root.setLevel(logging.INFO)
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.INFO)
	ch.setFormatter(logging.Formatter('%(message)s'))
	fh = logging.FileHandler(log_filename)
	fh.setLevel(logging.INFO)
	fh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
	root.addHandler(ch)
	root.addHandler(fh)

if __name__ == '__main__':
	main()
