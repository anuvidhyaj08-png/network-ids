import pandas as pd

df = pd.read_csv("packets.csv")
def detect_high_traffic(df):
    counts = df["src_ip"].value_counts()
    for ip, count in counts.items():
        if count>100:
            print(
                f"[ALERT] High traffic from {ip}"
            )

def detect_many_destinations(df):
    destinations=(
        df.groupby("src_ip")["dst_ip"]
          .nunique()
    )
    for ip, count in destinations.items():
        if count>50:
            print(
                f"[ALERT] Possible scan from {ip}"
            )
detect_high_traffic(df)
detect_many_destinations(df)
