import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from smishing.core import SmishingAnalyzer

class TestSmishing(unittest.TestCase):
    def test_detect(self):
        a=SmishingAnalyzer()
        r=a.analyze_message("URGENT: Your bank account is suspended. Verify immediately at http://bit.ly/fake")
        self.assertTrue(r["is_smishing"])
        self.assertGreater(r["risk_score"],30)
    def test_clean(self):
        a=SmishingAnalyzer()
        r=a.analyze_message("Hey, want to grab lunch today?")
        self.assertFalse(r["is_smishing"])
    def test_template(self):
        a=SmishingAnalyzer()
        r=a.generate_template("banking")
        self.assertIn("account",r["template"])

if __name__=="__main__": unittest.main()
