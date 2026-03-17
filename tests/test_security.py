import unittest
import os
import tempfile
import shutil
from nagra_parser import is_safe_path

class TestSecurity(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.safe_subdir = os.path.join(self.test_dir, "safe")
        os.mkdir(self.safe_subdir)

        # Create a dummy file in safe subdir
        self.safe_file = os.path.join(self.safe_subdir, "data.bin")
        with open(self.safe_file, "w") as f:
            f.write("safe data")

        # Create a sensitive file outside
        self.sensitive_file = os.path.join(self.test_dir, "sensitive.txt")
        with open(self.sensitive_file, "w") as f:
            f.write("sensitive data")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_is_safe_path_valid(self):
        self.assertTrue(is_safe_path(self.safe_file, self.safe_subdir))
        self.assertTrue(is_safe_path(os.path.join(self.safe_subdir, "new_file.bin"), self.safe_subdir))

    def test_is_safe_path_traversal(self):
        # Using ../ to try to access sensitive file
        traversal_path = os.path.join(self.safe_subdir, "..", "sensitive.txt")
        self.assertFalse(is_safe_path(traversal_path, self.safe_subdir))

    def test_is_safe_path_absolute_traversal(self):
        # Using absolute path to access sensitive file
        self.assertFalse(is_safe_path(self.sensitive_file, self.safe_subdir))

    def test_is_safe_path_same_dir(self):
        self.assertTrue(is_safe_path(self.safe_subdir, self.safe_subdir))

    def test_is_safe_path_parent_dir(self):
        self.assertFalse(is_safe_path(self.test_dir, self.safe_subdir))

    def test_is_safe_path_outside_cwd(self):
        # Even if base_dir is outside CWD, it should work if the file is within it
        self.assertTrue(is_safe_path(self.safe_file, self.safe_subdir))

if __name__ == '__main__':
    unittest.main()
