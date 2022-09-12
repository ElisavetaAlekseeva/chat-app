from django import forms
from .models import UserProfile, Chat


class ProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = '__all__'
        exclude = ['user', 'friends', 'user_friend']


class ChatForm(forms.ModelForm):
    body = forms.CharField(widget=forms.Textarea(attrs={'class': 'chat_form', 'placeholder': 'Type a message', 'rows': 3}))
    class Meta:
        model = Chat
        fields = ['body']
    

    