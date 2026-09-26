"""Load and combine the SMS spam datasets used for training."""

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
UCI_PATH = DATA_DIR / "sms_spam_collection.tsv"
PH_PATH = DATA_DIR / "ph_scam_augmentation.csv"
INTL_PATH = DATA_DIR / "international_scam_augmentation.csv"


def load_uci_dataset() -> pd.DataFrame:
    df = pd.read_csv(UCI_PATH, sep="\t", header=None, names=["label", "text"])
    df["source"] = "uci"
    return df


def load_ph_dataset() -> pd.DataFrame:
    df = pd.read_csv(PH_PATH)
    df["source"] = "ph_augmentation"
    return df


def load_international_dataset() -> pd.DataFrame:
    df = pd.read_csv(INTL_PATH)
    df["source"] = "international_augmentation"
    return df


def load_combined_dataset() -> pd.DataFrame:
    """Combine all sources, drop duplicates, and normalize labels."""
    df = pd.concat(
        [load_uci_dataset(), load_ph_dataset(), load_international_dataset()],
        ignore_index=True,
    )
    df["text"] = df["text"].str.strip()
    df = df.drop_duplicates(subset="text").reset_index(drop=True)
    df["label"] = df["label"].str.lower()
    assert set(df["label"].unique()) <= {"ham", "spam"}, "unexpected label values"
    return df


def train_test_split_df(df: pd.DataFrame, test_size: float = 0.2, seed: int = 42):
    return train_test_split(
        df,
        test_size=test_size,
        random_state=seed,
        stratify=df["label"],
    )


if __name__ == "__main__":
    combined = load_combined_dataset()
    print(combined["label"].value_counts())
    print(combined["source"].value_counts())
    print(f"Total: {len(combined)} messages")
