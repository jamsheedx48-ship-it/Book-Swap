from django.test import TestCase
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from apps.books.models import Book, Category

User = get_user_model()


class BookTest(TestCase):
    def setUp(self):
        self.client = APIClient()

        self.user = User.objects.create_user(
            name="User1",
            email="user1@test.com",
            password="123456",
            is_verified=True
        )

        self.other_user = User.objects.create_user(
            name="User2",
            email="user2@test.com",
            password="123456",
            is_verified=True
        )

        # authenticate user
        refresh = RefreshToken.for_user(self.user)
        self.client.cookies["access_token"] = str(refresh.access_token)

        # category
        self.category = Category.objects.create(name="Fiction")

        # book
        self.book = Book.objects.create(
            user=self.user,
            title="Test Book",
            author="Author",
            category=self.category,
            condition="new",
            description="desc"
        )


    # ---------------- LIST BOOKS ----------------
    def test_list_books(self):
        res = self.client.get("/api/books/")
        self.assertEqual(res.status_code, 200)
        self.assertTrue("results" in res.data)


    # ---------------- CREATE BOOK ----------------
    def test_create_book(self):
        res = self.client.post("/api/books/", {
            "title": "New Book",
            "author": "Author",
            "category": self.category.id,
            "condition": "new",
            "description": "desc"
        })

        self.assertEqual(res.status_code, 201)
        self.assertEqual(Book.objects.count(), 2)


    # ---------------- BOOK DETAIL ----------------
    def test_get_book_detail(self):
        res = self.client.get(f"/api/books/{self.book.id}/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["title"], "Test Book")


    # ---------------- UPDATE BOOK ----------------
    def test_update_book(self):
        res = self.client.put(f"/api/books/{self.book.id}/", {
            "title": "Updated Book"
        })

        self.assertEqual(res.status_code, 200)
        self.book.refresh_from_db()
        self.assertEqual(self.book.title, "Updated Book")


    # ---------------- DELETE (SOFT) ----------------
    def test_soft_delete(self):
        res = self.client.delete(f"/api/books/{self.book.id}/")
        self.assertEqual(res.status_code, 200)

        self.book.refresh_from_db()
        self.assertIsNotNone(self.book.deleted_at)


    # ---------------- TRASH LIST ----------------
    def test_trash_list(self):
        self.book.soft_delete()

        res = self.client.get("/api/books/trash/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.data), 1)


    # ---------------- RESTORE ----------------
    def test_restore_book(self):
        self.book.soft_delete()

        res = self.client.post(f"/api/books/trash/{self.book.id}/restore/")
        self.assertEqual(res.status_code, 200)

        self.book.refresh_from_db()
        self.assertIsNone(self.book.deleted_at)


    # ---------------- PERMANENT DELETE ----------------
    def test_permanent_delete(self):
        self.book.soft_delete()

        res = self.client.delete(f"/api/books/trash/{self.book.id}/delete/")
        self.assertEqual(res.status_code, 204)

        self.assertFalse(Book.objects.filter(id=self.book.id).exists())


    # ---------------- FILTER CATEGORY ----------------
    def test_filter_by_category(self):
        res = self.client.get(f"/api/books/?category={self.category.id}")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(len(res.data["results"]) >= 1)


    # ---------------- SEARCH ----------------
    def test_search(self):
        res = self.client.get("/api/books/?search=Test")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(len(res.data["results"]) >= 1)


    # ---------------- PERMISSION TEST ----------------
    def test_update_other_user_book(self):
        other_book = Book.objects.create(
            user=self.other_user,
            title="Other Book",
            author="Author",
            category=self.category,
            condition="new",
            description="desc"
        )

        res = self.client.put(f"/api/books/{other_book.id}/", {
            "title": "Hack"
        })

        self.assertEqual(res.status_code, 403)


    def test_delete_other_user_book(self):
        other_book = Book.objects.create(
            user=self.other_user,
            title="Other Book",
            author="Author",
            category=self.category,
            condition="new",
            description="desc"
        )

        res = self.client.delete(f"/api/books/{other_book.id}/")
        self.assertEqual(res.status_code, 403)


class CategoryTest(TestCase):
    def setUp(self):
        self.client = APIClient()

        self.category = Category.objects.create(name="Fiction")

    def test_list_categories(self):
        res = self.client.get("/api/books/categories/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.data), 1)