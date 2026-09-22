import os
import sys
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")
CHUNKS_DIR = os.path.join(DATA_DIR, "chunks")
DB_PATH = os.path.join(DATA_DIR, "pdxstorage.db")

print("Resetting database and storage...")

if os.path.exists(CHUNKS_DIR):
    shutil.rmtree(CHUNKS_DIR)
os.makedirs(CHUNKS_DIR, exist_ok=True)
with open(os.path.join(CHUNKS_DIR, ".gitkeep"), "w") as f:
    pass

for key_file in ["master.key", "auth.key", "antibot.key"]:
    p = os.path.join(DATA_DIR, key_file)
    if os.path.exists(p):
        os.remove(p)
        print(f"Removed key: {key_file}")

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)
    print("Removed old database file.")

from backend.database import Base, engine, run_migrations
Base.metadata.create_all(bind=engine)
run_migrations()
print("Initialized clean SQLite schema successfully.")

with open(os.path.join(DATA_DIR, ".gitkeep"), "w") as f:
    pass

print("Reset complete. Database is empty and ready for repository release.")
