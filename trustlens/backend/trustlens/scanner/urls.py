from django.urls import path

from .views import CheckURLView, HealthView

urlpatterns = [
    path("check-url/", CheckURLView.as_view(), name="check-url"),
    path("health/", HealthView.as_view(), name="health"),
]
