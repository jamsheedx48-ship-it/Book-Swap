import requests
from django.core.management.base import BaseCommand
from django.db.models import Q
from apps.books.models import Book
import google.generativeai as genai
from decouple import config


genai.configure(api_key=config("GEMINI_API_KEY"))


class Command(BaseCommand):
    help = "Fetch long descriptions using Google Books + LLM fallback"


    def get_google_description(self, book):
        query = f'intitle:{book.title} inauthor:{book.author}'
        url = "https://www.googleapis.com/books/v1/volumes"

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

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Google API failed: {e}")
            )

        return None


    def generate_llm_summary(self, book):
        try:
            model = genai.GenerativeModel("gemini-pro")

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

            response = model.generate_content(prompt)

            return response.text

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f"LLM summary failed for {book.title}: {e}"
                )
            )
            return None


    def handle(self, *args, **kwargs):
        books = Book.objects.filter(
            Q(long_description__isnull=True) |
            Q(long_description=""),
            deleted_at__isnull=True
        )

        self.stdout.write(
            f"Found {books.count()} books to process..."
        )

        for book in books:
            self.stdout.write(f"Processing: {book.title}")

            description = self.get_google_description(book)

            # fallback if missing or too short
            if not description or len(description) < 300:
                self.stdout.write(
                    f"Google summary too short for {book.title}, using LLM..."
                )
                description = self.generate_llm_summary(book)

            if description:
                book.long_description = description
                book.save(update_fields=["long_description"])

                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ Updated: {book.title}"
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f"Could not generate description for {book.title}"
                    )
                )

        self.stdout.write(
            self.style.SUCCESS("Done!")
        )