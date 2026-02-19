import sys
import os
import time

# Add parent directory to path to import Ferro_fixo
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import Ferro_fixo

class MockSerial:
    def __init__(self, response_delay=0.01, prompt=b'> '):
        self.response_delay = response_delay
        self.prompt_str = prompt
        self.buffer = b''
        self.last_write_time = 0
        self._in_waiting = 0

    def write(self, data):
        self.last_write_time = time.time()
        # Simulate device processing and adding prompt to buffer
        self.buffer += data # echo
        self.buffer += b'\n' + self.prompt_str

    @property
    def in_waiting(self):
        # Data becomes available after response_delay
        if time.time() - self.last_write_time >= self.response_delay:
            return len(self.buffer)
        return 0

    def read(self, size):
        available = self.in_waiting
        if available > 0:
            # Check how much we can actually read
            to_read = min(available, size)
            ret = self.buffer[:to_read]
            self.buffer = self.buffer[to_read:]
            return ret
        return b''

def run_benchmark():
    print("Running Benchmark...")
    print("Note: Baseline test will take about 45 seconds due to hardcoded sleeps.")

    # 1. Baseline
    print("1. Baseline (No prompt optimization)...")
    mock_ser = MockSerial(response_delay=0.01, prompt=b'> ')
    start_time = time.time()
    Ferro_fixo.run_exploit(mock_ser, prompt=None)
    baseline_duration = time.time() - start_time
    print(f"   Baseline Duration: {baseline_duration:.2f}s")

    # 2. Optimized
    print("2. Optimized (With prompt)...")
    mock_ser = MockSerial(response_delay=0.01, prompt=b'> ')
    start_time = time.time()
    Ferro_fixo.run_exploit(mock_ser, prompt=b'> ')
    optimized_duration = time.time() - start_time
    print(f"   Optimized Duration: {optimized_duration:.2f}s")

    improvement = baseline_duration - optimized_duration
    print(f"\nImprovement: {improvement:.2f}s ({baseline_duration/optimized_duration:.1f}x speedup)")

    if optimized_duration < baseline_duration * 0.1:
        print("SUCCESS: Optimization verified.")
    else:
        print("FAILURE: Optimization not significant.")

if __name__ == "__main__":
    run_benchmark()
