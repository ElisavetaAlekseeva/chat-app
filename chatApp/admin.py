from django.contrib import admin
from .models import UserProfile, Chat, FriendRequest, Friend
# Register your models here.

admin.site.register([UserProfile, Chat, FriendRequest, Friend])