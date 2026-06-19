from flask import Flask, render_template, redirect
import pandas as pd
import pyshark
import threading
import csv
import os
from datetime import datetime
app = Flask(__name__)
capture_running = False
def capture_packets():
    global capture_running
    capture = pyshark.LiveCapture(interface='wlp1s0')
    with open('packets.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        if os.path.getsize('packets.csv') == 0:
            writer.writerow([
                'timestamp',
                'src_ip',
                'dst_ip',
                'protocol',
                'length'
            ])
        while capture_running:
            try:
                for packet in capture.sniff_continuously(packet_count=1):
                    try:
                        writer.writerow([
                            datetime.now(),
                            packet.ip.src,
                            packet.ip.dst,
                            packet.transport_layer,
                            packet.length
                        ])

                        file.flush()
                    except AttributeError:
                        continue
            except Exception as e:
                print(e)

@app.route("/")
def home():

    try:
        df = pd.read_csv("packets.csv")

        total_packets = len(df)

        protocols = (
            df["protocol"]
            .value_counts()
            .to_dict()
        )

        top_ips = (
            df["src_ip"]
            .value_counts()
            .head(10)
            .to_dict()
        )

    except:
        total_packets = 0
        protocols = {}
        top_ips = {}

    return render_template(
        "index.html",
        total_packets=total_packets,
        protocols=protocols,
        top_ips=top_ips,
        capture_running=capture_running
    )


@app.route("/start", methods=["POST"])
def start():
    global capture_running
    if not capture_running:
        capture_running = True
        threading.Thread(
            target=capture_packets,
            daemon=True
        ).start()
    return redirect("/")
@app.route("/stop", methods=["POST"])
def stop():
    global capture_running
    capture_running = False
    return redirect("/")
if __name__ == "__main__":
    app.run(debug=True)
