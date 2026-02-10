"""Smishing Analysis Engine"""
import re,json,hashlib,urllib.parse
from datetime import datetime

class SmishingAnalyzer:
    INDICATORS={
        "urgency_words":["immediately","urgent","suspend","expire","verify now","action required","limited time"],
        "financial_keywords":["bank","account","credit","debit","wire","payment","transaction","SSN"],
        "threat_words":["locked","suspended","compromised","unauthorized","fraud","arrest","warrant"],
        "reward_words":["won","prize","gift","free","claim","congratulations","selected"],
    }
    
    def analyze_message(self,text):
        findings=[]
        score=0
        text_lower=text.lower()
        for category,keywords in self.INDICATORS.items():
            for kw in keywords:
                if kw in text_lower:
                    findings.append({"category":category,"keyword":kw})
                    score+=10
        urls=re.findall(r"https?://[\S]+",text)
        for url in urls:
            parsed=urllib.parse.urlparse(url)
            if any(s in parsed.netloc for s in ["bit.ly","tinyurl","t.co"]):
                findings.append({"category":"url_shortener","url":url}); score+=15
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",parsed.netloc):
                findings.append({"category":"ip_url","url":url}); score+=20
        return {"risk_score":min(score,100),"findings":findings,"is_smishing":score>=30}
    
    def generate_template(self,template_type):
        templates={
            "banking":"ALERT: Unusual activity on your account ending in XXXX. Verify at {url} or call {phone}",
            "delivery":"Your package #XXXXX is held. Update delivery preferences: {url}",
            "prize":"Congratulations! You've won a ${amount} gift card. Claim now: {url}",
            "verification":"Your verification code is {code}. If not requested, secure account: {url}",
        }
        return {"type":template_type,"template":templates.get(template_type,"Unknown type"),
                "purpose":"awareness_training_only"}

class SMSForensics:
    def extract_iocs(self,messages):
        iocs={"urls":[],"phones":[],"domains":[]}
        for msg in messages:
            text=msg.get("body","")
            iocs["urls"].extend(re.findall(r"https?://[\S]+",text))
            iocs["phones"].extend(re.findall(r"\+?\d{10,15}",text))
            for url in iocs["urls"]:
                domain=urllib.parse.urlparse(url).netloc
                if domain: iocs["domains"].append(domain)
        return {k:list(set(v)) for k,v in iocs.items()}
