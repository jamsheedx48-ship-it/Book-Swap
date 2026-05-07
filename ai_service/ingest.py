import os
import httpx
from dotenv import load_dotenv
from app.services.rag_handler import ingest_book

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")


def fetch_all_books():
    books = []
    url = f"{BACKEND_URL}/api/books/"

    while url:
        response = httpx.get(url)
        data = response.json()
        books.extend(data["results"])
        url = data.get("next")

    return books


def run():
    print("Fetching books from backend...")
    books = fetch_all_books()
    print(f"Found {len(books)} books")

    for book in books:
        book_id = book["id"]
        title = book["title"]
        author = book["author"]
        text = book.get("long_description", "")

        if not text:
            print(f"Skipping book {book_id} - no long_description")
            continue

        count = ingest_book(book_id, title, author, text)
        print(f"Ingested book '{title}' → {count} chunks")

    print("Done.")


if __name__ == "__main__":
    run()