"""
Database connection management with async SQLAlchemy and pgvector support.
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.pool import NullPool, QueuePool
from sqlalchemy import text
import logging

from src.config.settings import settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and sessions."""
    
    def __init__(self):
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None
    
    def create_engine(self) -> AsyncEngine:
        """Create async SQLAlchemy engine with pgvector support."""
        if self._engine is None:
            # Use NullPool for testing, QueuePool for production
            poolclass = NullPool if settings.environment == "testing" else QueuePool
            
            self._engine = create_async_engine(
                settings.database_url,
                echo=settings.debug,
                poolclass=poolclass,
                pool_size=settings.database_pool_size if poolclass == QueuePool else None,
                max_overflow=settings.database_max_overflow if poolclass == QueuePool else None,
                pool_pre_ping=True,  # Enable connection health checks
            )
            logger.info("Database engine created")
        
        return self._engine
    
    def get_sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        """Get session factory."""
        if self._sessionmaker is None:
            engine = self.create_engine()
            self._sessionmaker = async_sessionmaker(
                engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autocommit=False,
                autoflush=False,
            )
            logger.info("Session factory created")
        
        return self._sessionmaker
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session (dependency injection)."""
        sessionmaker = self.get_sessionmaker()
        async with sessionmaker() as session:
            try:
                yield session
            finally:
                await session.close()
    
    async def init_db(self):
        """Initialize database with pgvector extension."""
        engine = self.create_engine()
        async with engine.begin() as conn:
            # Enable pgvector extension
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            logger.info("pgvector extension enabled")
    
    async def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            engine = self.create_engine()
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    async def close(self):
        """Close database connections."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None
            logger.info("Database connections closed")


# Global database manager instance
db_manager = DatabaseManager()


# Dependency for FastAPI
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database sessions."""
    async for session in db_manager.get_session():
        yield session
