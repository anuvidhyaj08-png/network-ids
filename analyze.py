import pandas as pd

df = pd.read_csv("packets.csv")
print(df.head())
print("\nTotal packets:")
print(len(df))
print("\nProtocols:")
print(df["protocol"].value_counts())
print("\nTop Source IPs:")
print(df["src_ip"].value_counts().head(10))
ip_counts = df["src_ip"].value_counts()

for ip, count in ip_counts.items():
    if count > 100:
        print(f"⚠ High traffic from {ip}: {count} packets")
