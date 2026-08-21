"""db.py - database + API data flows (Python)."""
import requests

# Database connection to an external Postgres host (public IP).
# BOTH direction: the app writes rows and reads them back.
DATABASE_URL = "postgres://app_user:s3cr3t@52.20.16.7:5432/appdb"

# OUT: send metrics to a monitoring service
def report_metric(name, value):
    payload = {"metric": name, "value": value}
    requests.post("https://api.datadoghq.com/api/v1/series", json=payload)

# IN: fetch exchange rates from a third-party API
def get_rates(base="USD"):
    resp = requests.get(f"https://api.exchangerate.host/latest?base={base}")
    return resp.json()["rates"]
