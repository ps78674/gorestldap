from rest_framework import viewsets, permissions
from .models import User, Group
from .serializers import UserSerializer, GroupSerializer


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(is_active=True)
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]
    http_method_names = ['get', 'put']
    lookup_field = 'username'
    lookup_value_regex = r'[0-9a-z\-\_\.]+'


class GroupViewSet(viewsets.ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAdminUser]
    http_method_names = ['get', 'put']
    lookup_field = 'name'
    lookup_value_regex = r'[0-9a-z\-\_\.]+'
