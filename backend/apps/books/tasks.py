from celery import shared_task
from PIL import Image
import boto3
import io
import os
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

SIZES = {
    'thumbnail': (150, 200),
    'detail': (600, 800),
}

@shared_task
def process_book_image(image_name):
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME,
    )
    bucket = settings.AWS_STORAGE_BUCKET_NAME

    # Download original from S3
    response = s3.get_object(Bucket=bucket, Key=image_name)
    img_data = response['Body'].read()

    base, _ = os.path.splitext(image_name)

    with Image.open(io.BytesIO(img_data)) as img:
        img = img.convert('RGB')

        # Save WebP version
        webp_buffer = io.BytesIO()
        img.save(webp_buffer, 'WEBP', quality=85, optimize=True)
        webp_buffer.seek(0)
        s3.put_object(Bucket=bucket, Key=f"{base}.webp", Body=webp_buffer, ContentType='image/webp')

        # Save resized variants
        for name, size in SIZES.items():
            resized = img.copy()
            resized.thumbnail(size, Image.LANCZOS)
            buffer = io.BytesIO()
            resized.save(buffer, 'WEBP', quality=80)
            buffer.seek(0)
            s3.put_object(Bucket=bucket, Key=f"{base}_{name}.webp", Body=buffer, ContentType='image/webp')

    return {'status': 'done', 'base': base}


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
