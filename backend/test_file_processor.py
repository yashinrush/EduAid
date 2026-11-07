import sys
from unittest.mock import MagicMock

# Mock heavy NLP packages that have binary incompatibility with host numpy
for mod in [
    'spacy', 'torch', 'transformers', 'sense2vec', 'en_core_web_sm',
    'nltk', 'nltk.corpus', 'similarity.normalized_levenshtein',
    'Generator.mcq', 'Generator.encoding'
]:
    sys.modules[mod] = MagicMock()

import os
import unittest
import shutil
from Generator.main import FileProcessor

class MockFile:
    def __init__(self, filename, content=b""):
        self.filename = filename
        self.content = content

    def save(self, destination):
        with open(destination, "wb") as f:
            f.write(self.content)

class TestFileProcessorSecurity(unittest.TestCase):
    def setUp(self):
        self.test_upload_folder = "test_uploads/"
        self.processor = FileProcessor(upload_folder=self.test_upload_folder)

    def tearDown(self):
        if os.path.exists(self.test_upload_folder):
            shutil.rmtree(self.test_upload_folder)

    def test_process_valid_txt(self):
        mock_file = MockFile(filename="test_document.txt", content=b"Hello EduAid World")
        extracted = self.processor.process_file(mock_file)
        self.assertEqual(extracted, "Hello EduAid World")
        # Ensure temporary file was removed
        self.assertEqual(len(os.listdir(self.test_upload_folder)), 0)

    def test_path_traversal_prevention(self):
        # Malicious client sends path traversal in filename
        mock_file = MockFile(filename="../../traversal_attack.txt", content=b"attack content")
        extracted = self.processor.process_file(mock_file)
        self.assertEqual(extracted, "attack content")
        # File should NOT exist outside upload folder
        self.assertFalse(os.path.exists("../../traversal_attack.txt"))
        self.assertFalse(os.path.exists("traversal_attack.txt"))
        # Temporary file was securely removed from test upload folder
        self.assertEqual(len(os.listdir(self.test_upload_folder)), 0)

    def test_unsupported_extension_rejected(self):
        # Disallowed extensions should be rejected without saving
        for dangerous_name in ["script.py", "malware.exe", "exploit.sh", "notes.php"]:
            mock_file = MockFile(filename=dangerous_name, content=b"dangerous")
            extracted = self.processor.process_file(mock_file)
            self.assertEqual(extracted, "")
            self.assertEqual(len(os.listdir(self.test_upload_folder)), 0)

    def test_cleanup_on_exception(self):
        # Even if processing crashes, file must be removed
        class CrashingProcessor(FileProcessor):
            def extract_text_from_pdf(self, file_path):
                raise RuntimeError("Corrupt PDF decoding error")

        crashing_processor = CrashingProcessor(upload_folder=self.test_upload_folder)
        mock_file = MockFile(filename="corrupt.pdf", content=b"%PDF-corrupt")
        with self.assertRaises(RuntimeError):
            crashing_processor.process_file(mock_file)
        # Ensure the crashed file was cleaned up from disk
        self.assertEqual(len(os.listdir(self.test_upload_folder)), 0)

if __name__ == "__main__":
    unittest.main()
