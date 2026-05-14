from django.urls import path
from . import views

urlpatterns = [
    path('me/',views.MyProfileView.as_view(),name='public-profile'),
    path('<int:user_id>/', views.PublicProfileView.as_view(), name='public-profile'),
    path('<int:user_id>/ratings/', views.ListRatingsView.as_view(), name='list-ratings'),
    path('<int:user_id>/ratings/submit/', views.SubmitRatingView.as_view(), name='submit-rating'),
    path('<int:user_id>/ratings/delete/', views.DeleteRatingView.as_view(), name='delete-rating'),
    path('genres/', views.GenreListView.as_view(), name='genre-list'),
    path('activity/', views.RecentActivityView.as_view(), name='recent-activity'),

]
