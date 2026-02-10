from smishing.core import SmishingAnalyzer
a=SmishingAnalyzer()
messages=["URGENT: Account suspended! Verify at http://bit.ly/scam","Hey, dinner tonight?",
          "You won $1000! Claim at http://192.168.1.1/prize"]
for msg in messages:
    r=a.analyze_message(msg)
    print(f"[{'SMISH' if r['is_smishing'] else 'SAFE'}] Score: {r['risk_score']} - {msg[:40]}...")
