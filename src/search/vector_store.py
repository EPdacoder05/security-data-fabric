"""
pgvector storage and retrieval for semantic search.
Handles embeddings storage, indexing, and similarity search.
"""
import logging
import hashlib
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID, uuid4

from sqlalchemy import select, text, and_, or_, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
import numpy as np

from src.database.models import Embedding
from src.config.settings import settings

logger = logging.getLogger(__name__)


class VectorStoreError(Exception):
    """Base exception for vector store operations."""
    pass


class VectorStore:
    """
    pgvector-based vector storage and retrieval.
    
    Provides efficient storage, indexing, and semantic search capabilities
    using PostgreSQL with pgvector extension.
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize vector store.
        
        Args:
            session: Async SQLAlchemy session
        """
        self.session = session
        logger.debug("VectorStore initialized")
    
    async def create_index(
        self,
        lists: int = 100,
        recreate: bool = False
    ) -> None:
        """
        Create IVFFlat index for efficient similarity search.
        
        Args:
            lists: Number of lists for IVFFlat (recommend: rows/1000 for < 1M rows)
            recreate: Drop existing index before creating
        
        Raises:
            VectorStoreError: If index creation fails
        """
        try:
            index_name = "idx_embeddings_vector_ivfflat"
            
            if recreate:
                logger.info(f"Dropping existing index: {index_name}")
                await self.session.execute(
                    text(f"DROP INDEX IF EXISTS {index_name}")
                )
            
            logger.info(f"Creating IVFFlat index with {lists} lists")
            await self.session.execute(
                text(f"""
                    CREATE INDEX IF NOT EXISTS {index_name}
                    ON embeddings USING ivfflat (embedding vector_cosine_ops)
                    WITH (lists = {lists})
                """)
            )
            await self.session.commit()
            logger.info("IVFFlat index created successfully")
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to create index: {e}")
            raise VectorStoreError(f"Index creation failed: {e}")
    
    async def store_embedding(
        self,
        source_type: str,
        source_id: UUID,
        text_content: str,
        embedding: np.ndarray,
        model_version: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> UUID:
        """
        Store a single embedding with deduplication.
        
        Args:
            source_type: Type of source (incident, event, alert)
            source_id: UUID of source entity
            text_content: Text that was embedded
            embedding: Embedding vector
            model_version: Model version used
            metadata: Additional metadata
        
        Returns:
            UUID of stored embedding
        
        Raises:
            VectorStoreError: If storage fails
        """
        try:
            text_hash = self._compute_text_hash(text_content)
            
            # Check for existing embedding with same hash
            stmt = select(Embedding).where(
                and_(
                    Embedding.text_hash == text_hash,
                    Embedding.source_type == source_type,
                    Embedding.source_id == source_id
                )
            )
            result = await self.session.execute(stmt)
            existing = result.scalar_one_or_none()
            
            if existing:
                logger.debug(f"Embedding already exists for {source_type}:{source_id}, updating")
                existing.embedding = embedding.tolist()
                existing.model_version = model_version
                existing.metadata_json = metadata
                await self.session.commit()
                return existing.id
            
            # Create new embedding
            embedding_obj = Embedding(
                id=uuid4(),
                source_type=source_type,
                source_id=source_id,
                text_content=text_content,
                text_hash=text_hash,
                embedding=embedding.tolist(),
                model_version=model_version,
                metadata_json=metadata,
                created_at=datetime.utcnow()
            )
            
            self.session.add(embedding_obj)
            await self.session.commit()
            
            logger.debug(f"Stored embedding {embedding_obj.id} for {source_type}:{source_id}")
            return embedding_obj.id
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to store embedding: {e}")
            raise VectorStoreError(f"Storage failed: {e}")
    
    async def store_embeddings_batch(
        self,
        embeddings_data: List[Dict[str, Any]]
    ) -> List[UUID]:
        """
        Store multiple embeddings in batch with deduplication.
        
        Args:
            embeddings_data: List of dicts with keys:
                - source_type: str
                - source_id: UUID
                - text_content: str
                - embedding: np.ndarray
                - model_version: str
                - metadata: Optional[Dict]
        
        Returns:
            List of stored embedding UUIDs
        
        Raises:
            VectorStoreError: If batch storage fails
        """
        try:
            if not embeddings_data:
                return []
            
            stored_ids = []
            
            # Compute hashes for all embeddings
            for data in embeddings_data:
                data['text_hash'] = self._compute_text_hash(data['text_content'])
                data['id'] = uuid4()
            
            # Check for existing embeddings
            hashes = [data['text_hash'] for data in embeddings_data]
            stmt = select(Embedding).where(Embedding.text_hash.in_(hashes))
            result = await self.session.execute(stmt)
            existing_embeddings = {
                (e.text_hash, e.source_type, str(e.source_id)): e 
                for e in result.scalars().all()
            }
            
            # Separate updates and inserts
            updates = []
            inserts = []
            
            for data in embeddings_data:
                key = (data['text_hash'], data['source_type'], str(data['source_id']))
                
                if key in existing_embeddings:
                    # Update existing
                    existing = existing_embeddings[key]
                    existing.embedding = data['embedding'].tolist()
                    existing.model_version = data['model_version']
                    existing.metadata_json = data.get('metadata')
                    stored_ids.append(existing.id)
                else:
                    # Prepare insert
                    inserts.append({
                        'id': data['id'],
                        'source_type': data['source_type'],
                        'source_id': data['source_id'],
                        'text_content': data['text_content'],
                        'text_hash': data['text_hash'],
                        'embedding': data['embedding'].tolist(),
                        'model_version': data['model_version'],
                        'metadata': data.get('metadata'),
                        'created_at': datetime.utcnow()
                    })
                    stored_ids.append(data['id'])
            
            # Bulk insert new embeddings
            if inserts:
                stmt = insert(Embedding).values(inserts)
                await self.session.execute(stmt)
            
            await self.session.commit()
            
            logger.info(f"Stored {len(inserts)} new embeddings, updated {len(updates)}")
            return stored_ids
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to store embeddings batch: {e}")
            raise VectorStoreError(f"Batch storage failed: {e}")
    
    async def search(
        self,
        query_embedding: np.ndarray,
        limit: int = 10,
        source_type: Optional[str] = None,
        min_similarity: float = 0.0,
        metadata_filters: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[Embedding, float]]:
        """
        Search for similar embeddings using cosine similarity.
        
        Args:
            query_embedding: Query vector
            limit: Maximum results to return
            source_type: Filter by source type
            min_similarity: Minimum similarity threshold (0-1)
            metadata_filters: Additional metadata filters
        
        Returns:
            List of (Embedding, similarity_score) tuples, ordered by similarity
        
        Raises:
            VectorStoreError: If search fails
        """
        try:
            # Convert numpy array to list for pgvector
            query_vec = query_embedding.tolist()
            
            # Build query with cosine similarity operator (<=>)
            # Note: <=> returns distance (0 = identical, 2 = opposite)
            # We convert to similarity score: 1 - (distance / 2)
            stmt = select(
                Embedding,
                (1 - (Embedding.embedding.cosine_distance(query_vec) / 2)).label('similarity')
            )
            
            # Apply filters
            conditions = []
            if source_type:
                conditions.append(Embedding.source_type == source_type)
            
            if metadata_filters:
                for key, value in metadata_filters.items():
                    conditions.append(
                        Embedding.metadata_json[key].astext == str(value)
                    )
            
            if conditions:
                stmt = stmt.where(and_(*conditions))
            
            # Order by similarity (closest first) and limit
            stmt = stmt.order_by(
                Embedding.embedding.cosine_distance(query_vec)
            ).limit(limit)
            
            result = await self.session.execute(stmt)
            rows = result.all()
            
            # Filter by minimum similarity
            results = [
                (row[0], float(row[1])) 
                for row in rows 
                if float(row[1]) >= min_similarity
            ]
            
            logger.debug(f"Found {len(results)} similar embeddings (limit={limit})")
            return results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise VectorStoreError(f"Search failed: {e}")
    
    async def search_by_source_ids(
        self,
        source_ids: List[UUID],
        source_type: Optional[str] = None
    ) -> List[Embedding]:
        """
        Retrieve embeddings by source IDs.
        
        Args:
            source_ids: List of source entity UUIDs
            source_type: Optional source type filter
        
        Returns:
            List of matching embeddings
        
        Raises:
            VectorStoreError: If retrieval fails
        """
        try:
            stmt = select(Embedding).where(Embedding.source_id.in_(source_ids))
            
            if source_type:
                stmt = stmt.where(Embedding.source_type == source_type)
            
            result = await self.session.execute(stmt)
            embeddings = result.scalars().all()
            
            logger.debug(f"Retrieved {len(embeddings)} embeddings for {len(source_ids)} source IDs")
            return embeddings
            
        except Exception as e:
            logger.error(f"Failed to retrieve embeddings by source IDs: {e}")
            raise VectorStoreError(f"Retrieval failed: {e}")
    
    async def delete_by_source(
        self,
        source_type: str,
        source_id: UUID
    ) -> int:
        """
        Delete embeddings for a specific source.
        
        Args:
            source_type: Source type
            source_id: Source entity UUID
        
        Returns:
            Number of deleted embeddings
        
        Raises:
            VectorStoreError: If deletion fails
        """
        try:
            stmt = select(Embedding).where(
                and_(
                    Embedding.source_type == source_type,
                    Embedding.source_id == source_id
                )
            )
            result = await self.session.execute(stmt)
            embeddings = result.scalars().all()
            
            count = len(embeddings)
            for embedding in embeddings:
                await self.session.delete(embedding)
            
            await self.session.commit()
            
            logger.info(f"Deleted {count} embeddings for {source_type}:{source_id}")
            return count
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to delete embeddings: {e}")
            raise VectorStoreError(f"Deletion failed: {e}")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get vector store statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            # Total count
            count_stmt = select(func.count(Embedding.id))
            result = await self.session.execute(count_stmt)
            total_count = result.scalar()
            
            # Count by source type
            type_stmt = select(
                Embedding.source_type,
                func.count(Embedding.id)
            ).group_by(Embedding.source_type)
            result = await self.session.execute(type_stmt)
            by_type = {row[0]: row[1] for row in result.all()}
            
            # Recent embeddings (last 24 hours)
            from datetime import timedelta
            recent_stmt = select(func.count(Embedding.id)).where(
                Embedding.created_at >= datetime.utcnow() - timedelta(hours=24)
            )
            result = await self.session.execute(recent_stmt)
            recent_count = result.scalar()
            
            stats = {
                'total_embeddings': total_count,
                'by_source_type': by_type,
                'recent_24h': recent_count,
                'embedding_dimension': 384  # Based on model
            }
            
            logger.debug(f"Statistics: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                'total_embeddings': 0,
                'by_source_type': {},
                'recent_24h': 0,
                'error': str(e)
            }
    
    async def update_model_version(
        self,
        old_version: str,
        new_version: str
    ) -> int:
        """
        Update model version for embeddings (for versioning support).
        
        Args:
            old_version: Old model version
            new_version: New model version
        
        Returns:
            Number of updated embeddings
        
        Raises:
            VectorStoreError: If update fails
        """
        try:
            stmt = select(Embedding).where(Embedding.model_version == old_version)
            result = await self.session.execute(stmt)
            embeddings = result.scalars().all()
            
            count = len(embeddings)
            for embedding in embeddings:
                embedding.model_version = new_version
            
            await self.session.commit()
            
            logger.info(f"Updated {count} embeddings from {old_version} to {new_version}")
            return count
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to update model version: {e}")
            raise VectorStoreError(f"Version update failed: {e}")
    
    def _compute_text_hash(self, text: str) -> str:
        """
        Compute SHA-256 hash of text for deduplication.
        
        Args:
            text: Text to hash
        
        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
