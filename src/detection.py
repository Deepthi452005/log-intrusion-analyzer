import pandas as pd
from datetime import timedelta


def detect_bruteforce_ssh(ssh_df: pd.DataFrame,
                          attempts_threshold: int = 5,
                          window_minutes: int = 5) -> pd.DataFrame:
    """
    Simple brute-force detection:
    - group by IP in time windows
    - flag if failed attempts >= attempts_threshold
    """
    if ssh_df.empty:
        return pd.DataFrame()

    ssh_df = ssh_df.dropna(subset=["time"]).copy()
    ssh_df["time_window"] = ssh_df["time"].dt.floor(f"{window_minutes}min")

    grouped = ssh_df.groupby(["ip", "time_window"]).size().reset_index(name="failed_attempts")

    suspects = grouped[grouped["failed_attempts"] >= attempts_threshold].copy()
    if suspects.empty:
        return suspects

    suspects["category"] = "SSH Brute Force"
    suspects["details"] = suspects["failed_attempts"].astype(str) + \
        f" failed logins within {window_minutes} min"

    suspects = suspects.rename(columns={"time_window": "time"})
    return suspects[["time", "ip", "category", "details"]]


def detect_scanning_apache(apache_df: pd.DataFrame,
                           urls_threshold: int = 20) -> pd.DataFrame:
    """
    Detect scanning:
    - IPs hitting many distinct URLs
    """
    if apache_df.empty:
        return pd.DataFrame()

    grouped = apache_df.groupby("ip")["url"].nunique().reset_index(name="unique_urls")
    suspects = grouped[grouped["unique_urls"] >= urls_threshold].copy()
    if suspects.empty:
        return suspects

    suspects["time"] = pd.NaT  # unknown specific time
    suspects["category"] = "Web Scanning"
    suspects["details"] = suspects["unique_urls"].astype(str) + " unique URLs accessed"

    return suspects[["time", "ip", "category", "details"]]


def detect_dos_apache(apache_df: pd.DataFrame,
                      requests_threshold: int = 100,
                      window_minutes: int = 1) -> pd.DataFrame:
    """
    Detect basic DoS:
    - IPs making many requests per minute
    """
    if apache_df.empty:
        return pd.DataFrame()

    apache_df = apache_df.dropna(subset=["time"]).copy()
    apache_df["time_window"] = apache_df["time"].dt.floor(f"{window_minutes}min")

    grouped = apache_df.groupby(["ip", "time_window"]).size().reset_index(name="request_count")
    suspects = grouped[grouped["request_count"] >= requests_threshold].copy()
    if suspects.empty:
        return suspects

    suspects["category"] = "Possible DoS"
    suspects["details"] = suspects["request_count"].astype(str) + \
        f" requests within {window_minutes} min"

    suspects = suspects.rename(columns={"time_window": "time"})
    return suspects[["time", "ip", "category", "details"]]


def cross_reference_blacklist(alerts_df: pd.DataFrame, blacklist_ips: set) -> pd.DataFrame:
    """
    Mark alerts where IP is in blacklist.
    """
    if alerts_df.empty:
        return alerts_df

    alerts_df = alerts_df.copy()
    alerts_df["blacklisted"] = alerts_df["ip"].isin(blacklist_ips)
    return alerts_df
