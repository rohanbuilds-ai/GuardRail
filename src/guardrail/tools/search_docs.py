"""Tool 1: search_incident_documents

Purpose:
Search approved synthetic incident documentation (triage notes, reports, runbooks).

Security Principles:
1. Strict Input Validation: Query length is bounded, incident_id must match regex, limit is capped at 20.
2. Parameterized Database Queries: No SQL concatenation.
3. Untrusted Data Classification: All returned documents are explicitly tagged with their
   classification and trust status to remind downstream agents that document contents
   must never be interpreted as execution instructions.
"""

import sqlite3
from typing import List, Optional
from pydantic import BaseModel, Field
from guardrail.storage.database import search_documents_db


class SearchDocsInput(BaseModel):
    """Validated input parameters for the document search tool."""

    query: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Search keyword or term to match in titles or contents",
    )
    incident_id: Optional[str] = Field(
        None,
        pattern=r"^INC-\d{3}$",
        description="Optional filter by incident ID (e.g. INC-001)",
    )
    limit: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of document records to return (1-20)",
    )


class DocumentExcerpt(BaseModel):
    """Structured, untrusted document excerpt returned to the caller."""

    id: str
    incident_id: str
    title: str
    doc_type: str
    classification: str
    excerpt: str
    trust_level: str = "untrusted_retrieved_data"


class SearchDocsOutput(BaseModel):
    """Output envelope returned by search_incident_documents."""

    query: str
    incident_id: Optional[str]
    total_found: int
    documents: List[DocumentExcerpt]


def search_incident_documents(
    input_params: SearchDocsInput,
    conn: sqlite3.Connection,
) -> SearchDocsOutput:
    """Execute bounded search over synthetic incident documents."""
    docs = search_documents_db(
        conn=conn,
        query=input_params.query,
        incident_id=input_params.incident_id,
        limit=input_params.limit,
    )

    excerpts = [
        DocumentExcerpt(
            id=doc.id,
            incident_id=doc.incident_id,
            title=doc.title,
            doc_type=doc.doc_type,
            classification=doc.classification,
            # Provide bounded excerpt up to 300 characters
            excerpt=doc.content[:300] + ("..." if len(doc.content) > 300 else ""),
        )
        for doc in docs
    ]

    return SearchDocsOutput(
        query=input_params.query,
        incident_id=input_params.incident_id,
        total_found=len(excerpts),
        documents=excerpts,
    )
