import json
import os
from groq import Groq

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

async def get_recommendations(interests: list[str], swapped_books: list[str], user_id: str) -> list[dict]:
    context_parts = []

    if interests:
        context_parts.append(f"User's genre interests: {', '.join(interests)}")
    if swapped_books:
        context_parts.append(f"Books the user has swapped: {', '.join(swapped_books)}")
    if not context_parts:
        context_parts.append("No history available. Recommend popular books across genres.")

    user_context = "\n".join(context_parts)

    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a book recommendation assistant. "
                    "Based on the user's reading history and interests, recommend exactly 4 books. "
                    "Respond ONLY with a valid JSON array. No markdown, no explanation, no backticks. "
                    "Each object must have: title, author, genre, reason (1 sentence), cover_emoji. "
                    'Example: [{"title":"Dune","author":"Frank Herbert","genre":"Science Fiction","reason":"Epic world-building.","cover_emoji":"🏜️"}]'
                ),
            },
            {
                "role": "user",
                "content": f"{user_context}\n\nGive me 4 book recommendations."
            }
        ],
        temperature=0.7,
    )

    raw = completion.choices[0].message.content.strip()
    return json.loads(raw)