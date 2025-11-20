from pathlib import Path
import pandas as pd
from datetime import datetime


def export_alerts_to_csv(alerts_df: pd.DataFrame, reports_dir: str = "../reports") -> Path:
    """
    Export alerts to CSV file in reports_dir.
    Returns the Path of created file.
    """
    reports_path = Path(reports_dir)
    reports_path.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = reports_path / f"alerts_{ts}.csv"
    alerts_df.to_csv(file_path, index=False)
    return file_path
