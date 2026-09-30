from __future__ import annotations

from uuid import uuid5, NAMESPACE_URL

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)
from sentence_transformers import SentenceTransformer

from threatgraph.models.schema import RetrievalDocument


class VectorRetriever:

    COLLECTION_NAME = "threatgraph"

    def __init__(self) -> None:

        # Qdrant will store its database locally
        # inside this directory.
        self.client = QdrantClient(
            path=".qdrant"
        )

        # Lightweight embedding model.
        self.model = SentenceTransformer(
            "sentence-transformers/all-MiniLM-L6-v2"
        )

        self.vector_size = (
            self.model.get_sentence_embedding_dimension()
        )

    def create_collection(self) -> None:
        """
        Create the Qdrant vector collection if
        it does not already exist.
        """

        if not self.client.collection_exists(
            self.COLLECTION_NAME
        ):
            self.client.create_collection(
                collection_name=self.COLLECTION_NAME,
                vectors_config=VectorParams(
                    size=self.vector_size,
                    distance=Distance.COSINE,
                ),
            )

    def index_documents(
        self,
        documents: list[RetrievalDocument],
    ) -> None:
        """
        Embed documents and store them in Qdrant.
        """

        self.create_collection()

        texts = [
            document.text
            for document in documents
        ]

        vectors = self.model.encode(
            texts,
            show_progress_bar=True,
        )

        points = []

        for document, vector in zip(
            documents,
            vectors,
        ):
            # Qdrant needs a valid point ID.
            # We deterministically convert our document ID
            # into a UUID.
            point_id = str(
                uuid5(
                    NAMESPACE_URL,
                    document.id,
                )
            )

            points.append(
                PointStruct(
                    id=point_id,
                    vector=vector.tolist(),
                    payload={
                        "document_id": document.id,
                        "title": document.title,
                        "text": document.text,
                        "document_type": (
                            document.document_type
                        ),
                        "source": document.source,
                        "metadata": document.metadata,
                    },
                )
            )

        self.client.upsert(
            collection_name=self.COLLECTION_NAME,
            points=points,
        )

    def search(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[dict]:
        """
        Perform semantic vector search.
        """

        query_vector = self.model.encode(
            query
        ).tolist()

        result = self.client.query_points(
            collection_name=self.COLLECTION_NAME,
            query=query_vector,
            limit=top_k,
        )

        return [
            {
                "score": point.score,
                **point.payload,
            }
            for point in result.points
        ]