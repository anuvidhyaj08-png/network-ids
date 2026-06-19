import pyshark
import csv
import os
from datetime import datetime

capture=pyshark.LiveCapture(interface='wlp1s0')

with open('packets.csv', 'a', newline='') as file:
    writer=csv.writer(file)
    if os.path.getsize('packets.csv')==0:
        writer.writerow([
            'timestamp',
            'src_ip',
            'dst_ip',
            'protocol',
            'length'
        ])
    for packet in capture.sniff_continuously():
        try:
            row=[
                datetime.now(),
                packet.ip.src,
                packet.ip.dst,
                packet.transport_layer,
                packet.length
            ]
            writer.writerow(row)
            print(row)
        except AttributeError:
            continue
