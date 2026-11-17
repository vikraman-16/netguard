"""Run all Python tests:  python tests/run_tests.py   (add -k name to filter)"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py")
    if "-k" in sys.argv:
        key = sys.argv[sys.argv.index("-k") + 1]

        def keep(s):
            out = unittest.TestSuite()
            for t in s:
                if isinstance(t, unittest.TestSuite):
                    out.addTests(keep(t))
                elif key in t.id():
                    out.addTest(t)
            return out
        suite = keep(suite)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
