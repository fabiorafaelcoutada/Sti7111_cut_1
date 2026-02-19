import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import io

# Add parent directory to path to import Ferro_fixo
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Ferro_fixo

class TestFerroFixo(unittest.TestCase):
    def test_execution_matches_original(self):
        """
        Verifies that running the new script produces the same sequence of
        serial writes and sleep calls as the original script.
        """

        # Load expected output
        expected_calls = []
        with open("tests/expected_output.txt", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("WRITE: "):
                    # Extract the bytes literal string representation
                    # WRITE: b'poke ...\n'
                    # We need to evaluate the repr to get bytes
                    val_str = line[7:] # Remove "WRITE: "
                    try:
                        # ast.literal_eval handles b'...' safely
                        import ast
                        val = ast.literal_eval(val_str)
                        expected_calls.append(('write', val))
                    except:
                        self.fail(f"Could not parse expected WRITE line: {line}")

                elif line.startswith("SLEEP: "):
                    duration = float(line.split(": ")[1])
                    expected_calls.append(('sleep', duration))

        # Capture calls from the new script
        captured_calls = []

        # Mock serial.Serial
        mock_serial = MagicMock()
        mock_serial_instance = MagicMock()
        mock_serial.return_value = mock_serial_instance

        def side_effect_write(data):
            captured_calls.append(('write', data))
            return len(data)

        mock_serial_instance.write.side_effect = side_effect_write

        # Mock time.sleep
        def side_effect_sleep(seconds):
            captured_calls.append(('sleep', seconds))

        # Patch everything
        with patch('serial.Serial', mock_serial), \
             patch('time.sleep', side_effect=side_effect_sleep), \
             patch('sys.stdout', new_callable=io.StringIO), \
             patch('sys.argv', ['Ferro_fixo.py', '--payload', 'payload.txt']):

            # Execute main
            Ferro_fixo.main()

        # Verify length
        self.assertEqual(len(captured_calls), len(expected_calls),
                         f"Mismatch in number of calls: {len(captured_calls)} vs {len(expected_calls)}")

        # Verify sequence
        for i, (captured, expected) in enumerate(zip(captured_calls, expected_calls)):
            self.assertEqual(captured, expected, f"Mismatch at call {i}: Expected {expected}, Got {captured}")

if __name__ == '__main__':
    unittest.main()
