from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session
import datetime
import os

os.makedirs("data", exist_ok=True)

DATABASE_URL = "sqlite:///./data/pdxstorage.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    totp_secret = Column(String, nullable=True)
    retention_days = Column(Integer, default=0)
    cyclic_storage = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    custom_quota_bytes = Column(Integer, default=21474836480)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String, index=True)
    total_size = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    owner = relationship("User")
    chunks = relationship("FileChunkMapping", back_populates="file", order_by="FileChunkMapping.sequence_order", cascade="all, delete-orphan")

class Chunk(Base):
    __tablename__ = "chunks"
    id = Column(Integer, primary_key=True, index=True)
    chunk_hash = Column(String, unique=True, index=True)
    size = Column(Integer)

class FileChunkMapping(Base):
    __tablename__ = "file_chunk_mappings"
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    chunk_id = Column(Integer, ForeignKey("chunks.id"))
    sequence_order = Column(Integer)

    file = relationship("File", back_populates="chunks")
    chunk = relationship("Chunk")

Base.metadata.create_all(bind=engine)

def run_migrations():
    import sqlite3
    try:
        conn = sqlite3.connect("data/pdxstorage.db")
        cursor = conn.cursor()
        columns = [col[1] for col in cursor.execute("PRAGMA table_info(users)").fetchall()]
        if "retention_days" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN retention_days INTEGER DEFAULT 0")
            conn.commit()
        if "cyclic_storage" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN cyclic_storage BOOLEAN DEFAULT 0")
            conn.commit()
        if "is_blocked" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN is_blocked BOOLEAN DEFAULT 0")
            conn.commit()
        if "custom_quota_bytes" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN custom_quota_bytes INTEGER DEFAULT 21474836480")
            conn.commit()
        conn.close()
    except Exception as e:
        print("Erro na migração do banco:", e)

run_migrations()

def delete_file_and_cleanup_chunks(db: Session, file: File):
    
    from backend.storage import delete_physical_chunk
    
    chunk_ids = [m.chunk_id for m in file.chunks]
    
    db.delete(file)
    db.commit()
    
    for c_id in chunk_ids:
        remaining = db.query(FileChunkMapping).filter(FileChunkMapping.chunk_id == c_id).count()
        if remaining == 0:
            chunk = db.query(Chunk).filter(Chunk.id == c_id).first()
            if chunk:
                delete_physical_chunk(chunk.chunk_hash)
                db.delete(chunk)
    db.commit()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()