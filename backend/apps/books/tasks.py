from celery import shared_task
from PIL import Image
import boto3
import io
import os
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from apps.books.models import Book
from apps.books.services.book_enrichment import enrich_book
import httpx

SIZES = {
    'thumbnail': (300, 400),
    'detail': (800, 1067),
}

@shared_task
def process_book_image(book_id, image_name):
    from .models import Book
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME,
        )
        bucket = settings.AWS_STORAGE_BUCKET_NAME

        response = s3.get_object(Bucket=bucket, Key=image_name)
        img_data = response['Body'].read()

        base, _ = os.path.splitext(image_name)
        filename = os.path.basename(base)

        book = Book.objects.get(id=book_id)

        with Image.open(io.BytesIO(img_data)) as img:
            img = img.convert('RGB')

            # Save WebP version of original
            webp_key = f"books/original/{filename}.webp"
            webp_buffer = io.BytesIO()
            img.save(webp_buffer, 'WEBP', quality=90, optimize=True)
            webp_buffer.seek(0)
            s3.put_object(Bucket=bucket, Key=webp_key, Body=webp_buffer, ContentType='image/webp')
            book.image = webp_key

            # Save resized variants
            for name, size in SIZES.items():
                resized = img.copy()
                if resized.width > size[0] or resized.height > size[1]:
                    resized.thumbnail(size, Image.LANCZOS)
                buffer = io.BytesIO()
                quality = 85 if name == 'thumbnail' else 90
                resized.save(buffer, 'WEBP', quality=quality)
                buffer.seek(0)

                if name == 'thumbnail':
                    key = f"books/thumbnails/{filename}_{name}.webp"
                    book.image_thumbnail = key
                elif name == 'detail':
                    key = f"books/detail/{filename}_{name}.webp"
                    book.image_detail = key

                s3.put_object(Bucket=bucket, Key=key, Body=buffer, ContentType='image/webp')

        book.save()
        s3.delete_object(Bucket=bucket, Key=image_name)

        return {'status': 'done', 'base': base}

    except Exception as e:
        return {'status': 'error', 'reason': str(e)}


@shared_task
def purge_trashed_books():
    from .models import Book
    cutoff = timezone.now() - timedelta(days=30)
    books = Book.objects.filter(deleted_at__isnull=False, deleted_at__lte=cutoff)

    count = 0
    for book in books:
        if book.image:
            book.image.delete(save=False)
        book.delete()
        count += 1

    return f"Purged {count} books"


# for long desc
@shared_task
def enrich_book_description_task(book_id):
    try:
        book = Book.objects.get(id=book_id)
        print(f"Running enrichment for: {book.title}")
        success= enrich_book(book)
        
        # trigger ingest after long_description is saved
        if success:
            ingest_book_to_qdrant.delay(
                book_id,
                book.title,
                book.author,
                book.long_description
            )

    except Book.DoesNotExist:
        print(f"Book {book_id} not found")


@shared_task(bind=True, max_retries=3)
def ingest_book_to_qdrant(self, book_id, title, author, text):
    try:
        response = httpx.post(
            "http://ai_service:8001/api/ai/ingest",
            json={
                "book_id": book_id,
                "title": title,
                "author": author,
                "text": text
            },
            timeout=30
        )
        response.raise_for_status()
        print(f"✓ Ingested '{title}' into Qdrant")
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)