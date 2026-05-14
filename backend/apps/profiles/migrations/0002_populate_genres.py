from django.db import migrations

GENRES = [
    'literary_fiction', 'science_fiction', 'fantasy', 'mystery',
    'thriller', 'romance', 'horror', 'history', 'biography',
    'self_help', 'philosophy', 'science', 'technology', 'poetry', 'comics',
]

def populate_genres(apps, schema_editor):
    Genre = apps.get_model('profiles', 'Genre')
    for genre in GENRES:
        Genre.objects.get_or_create(name=genre)

class Migration(migrations.Migration):
    dependencies = [('profiles', '0001_initial')]
    operations = [migrations.RunPython(populate_genres)]