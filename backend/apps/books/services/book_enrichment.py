import requests
from google import genai
from decouple import config
import time
client = genai.Client(api_key=config("GEMINI_API_KEY"))



def get_google_description(book):
    query = f'intitle:{book.title} inauthor:{book.author}'
    url = "https://www.googleapis.com/books/v1/volumes"

    for attempt in range(2):  # retry once
        try:
            response = requests.get(
                url,
                params={"q": query},
                timeout=10
            )
            response.raise_for_status()

            data = response.json()
            items = data.get("items", [])

            for item in items:
                volume_info = item.get("volumeInfo", {})

                language = volume_info.get("language", "")
                description = volume_info.get("description", "")

                if language == "en" and description:
                    return description

        except requests.exceptions.HTTPError as e:
            print(f"Google API failed ({attempt+1}) for {book.title}: {e}")
            time.sleep(1)  # small delay before retry

    return None


def generate_llm_summary(book):
    try:

        prompt = f"""
        Generate a detailed summary for this book:

        Title: {book.title}
        Author: {book.author}

        Include:
        - overview
        - key concepts
        - important takeaways

        Keep it under 500 words.
        """

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        print("Gemini response:", response.text)
        return response.text.strip().strip('"')

    except Exception as e:
        print(f"LLM summary failed for {book.title}: {e}")
        return None


def enrich_book(book):
    description = get_google_description(book)

    if not description:
        description = generate_llm_summary(book)

    elif len(description) < 300:
        print(f"Google summary too short for {book.title}, trying LLM...")
        
        llm_description = generate_llm_summary(book)

        if llm_description:
            description = llm_description

    if description and description.strip():
        book.long_description = description.strip()
        book.save(update_fields=["long_description"])
        print(f"✓ Updated {book.title}")
        return True

    print(f"Could not generate description for {book.title}")
    return False