"""User management endpoint tests."""

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from tests.factories import UserFactory

User = get_user_model()


@pytest.mark.django_db
class TestUserDelete:
    def test_admin_cannot_delete_self(self, api_client, admin_user):
        """A user cannot delete their own account."""
        token = RefreshToken.for_user(admin_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")

        url = f"/api/auth/users/{admin_user.id}/"
        response = api_client.delete(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.data["detail"] == "You cannot delete your own account."
        assert User.objects.filter(id=admin_user.id).exists()

    def test_admin_can_delete_other_user(self, api_client, admin_user, employee_user):
        """A regular admin can delete another non-superuser account."""
        token = RefreshToken.for_user(admin_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")

        url = f"/api/auth/users/{employee_user.id}/"
        response = api_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not User.objects.filter(id=employee_user.id).exists()

    def test_admin_cannot_delete_superuser(self, api_client, admin_user):
        """No admin can delete the system superuser account."""
        # Create a superuser (the system bootstrap admin)
        superuser = UserFactory(role="ADMIN", is_staff=True, is_superuser=True)

        # A regular admin (is_superuser=False) tries to delete the superuser
        token = RefreshToken.for_user(admin_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")

        url = f"/api/auth/users/{superuser.id}/"
        response = api_client.delete(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.data["detail"] == "The system super admin account cannot be deleted."
        # Confirm the superuser still exists
        assert User.objects.filter(id=superuser.id).exists()

    def test_superuser_cannot_delete_another_superuser(self, api_client):
        """Even a superuser cannot delete another superuser account."""
        superuser_a = UserFactory(role="ADMIN", is_staff=True, is_superuser=True)
        superuser_b = UserFactory(role="ADMIN", is_staff=True, is_superuser=True)

        token = RefreshToken.for_user(superuser_a)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")

        url = f"/api/auth/users/{superuser_b.id}/"
        response = api_client.delete(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert User.objects.filter(id=superuser_b.id).exists()


@pytest.mark.django_db
class TestUserUpdate:
    def test_admin_cannot_update_superuser(self, api_client, admin_user):
        """A regular admin cannot update a superuser account."""
        superuser = UserFactory(role="ADMIN", is_staff=True, is_superuser=True)

        token = RefreshToken.for_user(admin_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")

        url = f"/api/auth/users/{superuser.id}/"
        payload = {"first_name": "UpdatedName"}
        response = api_client.patch(url, payload)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.data["detail"] == "The system super admin account cannot be updated."
        
        # Confirm not updated on DB
        superuser.refresh_from_db()
        assert superuser.first_name != "UpdatedName"

    def test_superuser_can_update_self(self, api_client):
        """A superuser can update their own account details."""
        superuser = UserFactory(role="ADMIN", is_staff=True, is_superuser=True)

        token = RefreshToken.for_user(superuser)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")

        url = f"/api/auth/users/{superuser.id}/"
        payload = {"first_name": "NewSuperName"}
        response = api_client.patch(url, payload)

        assert response.status_code == status.HTTP_200_OK
        superuser.refresh_from_db()
        assert superuser.first_name == "NewSuperName"

