import os
from groq import Groq
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue
from google import genai
from google.genai import types


QDRANT_HOST = os.getenv("QDRANT_HOST", "qdrant")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", 6333))
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
COLLECTION_NAME = "books"

# embedding gemini
client_gemini = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)
qdrant = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
groq_client = Groq(api_key=GROQ_API_KEY)

#chunking
def split_text(text: str, chunk_size: int = 500, chunk_overlap: int = 50) -> list[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - chunk_overlap
    return chunks

def ensure_collection():
    existing = [c.name for c in qdrant.get_collections().collections]
    if COLLECTION_NAME not in existing:
        qdrant.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=768, distance=Distance.COSINE),
        )


def ingest_book(book_id: int, title: str, author: str, text: str):
    ensure_collection()
    chunks = split_text(text)
    points = []
    for i, chunk in enumerate(chunks):
        result= client_gemini.models.embed_content(
            model="gemini-embedding-001",
            contents=chunk,
            config=types.EmbedContentConfig(output_dimensionality=768)
        )
        vector= result.embeddings[0].values
        points.append(
            PointStruct(
                id=book_id * 10000 + i,
                vector=vector,
                payload={
                    "book_id": book_id,
                    "title": title,
                    "author": author,
                    "chunk": chunk,
                },
            )
        )

    qdrant.upsert(collection_name=COLLECTION_NAME, points=points)
    return len(points)


def ask_book(book_id: int, question: str, user_id: str, book_title: str) -> str:
    from app.services.dynamo_handler import save_message

    # save user question
    save_message(user_id, book_id, book_title, "user", question)

    result = client_gemini.models.embed_content(
        model="gemini-embedding-001",
        contents=question,
        config=types.EmbedContentConfig(output_dimensionality=768)
    )
    question_vector = result.embeddings[0].values

    results = qdrant.query_points(
        collection_name=COLLECTION_NAME,
        query=question_vector,
        query_filter=Filter(
            must=[FieldCondition(key="book_id", match=MatchValue(value=book_id))]
        ),
        limit=4,
    ).points

    if not results:
        answer = "No relevant content found for this book."
        save_message(user_id, book_id, book_title, "assistant", answer)
        return answer

    context = "\n\n".join([r.payload["chunk"] for r in results])

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant that answers questions based only on the provided book content.",
            },
            {
                "role": "user",
                "content": f"Book: {results[0].payload['title']} by {results[0].payload['author']}\n\nContext:\n{context}\n\nQuestion: {question}",
            },
        ],
    )

    answer = response.choices[0].message.content
    save_message(user_id, book_id, book_title, "assistant", answer)
    return answer