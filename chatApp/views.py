from base64 import urlsafe_b64decode
from calendar import c
from cmath import e
from tokenize import generate_tokens
from urllib import response
from venv import create
from wsgiref.util import request_uri
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.forms import UserCreationForm,AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib import messages
from .forms import ProfileForm, ChatForm
from .models import UserProfile, Chat, FriendRequest, Friend
from itertools import chain
from django.contrib.auth import logout, login
from django.http import JsonResponse
import json
from chat import settings
from django.core.mail import EmailMessage, send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import generate_token


def signup(request):

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if password == password2:
            if User.objects.filter(username=username).exists():
                messages.info(request, 'This username already exist')
                return redirect('signup')

            # elif User.objects.filter(email=email).exists():
            #     return redirect('signup')

            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()

                user_login = authenticate(username=username, password=password)
                login(request, user_login)

                user_model = User.objects.get(username=username)
                user_profile = UserProfile.objects.create(user_id = user_model.id)
                user_profile.name = username
                user.is_active = False

                user_profile.save()

                # messages.success(request, 'Your account has been successfully created. We have sent you a confirmation email, please confirm your email address in order to activate your account.')

                # EMAIL
                # subject = 'Welcome to Lisa Chat App!'
                # message = f'Hello {user.username}! \n Welcome to Lisa Chat App! \n We sent you a confirmation email, please confirm your email address in order to activate your account.'
                # from_email = settings.EMAIL_HOST_USER
                # to_list = [user.email]
                # send_mail(subject, message, from_email, to_list, fail_silently=True)

                # current_site = get_current_site(request)
                # email_subject = 'Confirm your email @ Lisa Chat App'
                # message2 = render_to_string('email_confirmation.html', {
                #             'name': user.username,
                #             'domain': current_site.domain,
                #             'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                #             'token': generate_token.make_token(user)
                #             })

                # email = EmailMessage(
                #     email_subject,
                #     message2,
                #     settings.EMAIL_HOST_USER,
                #     [user.email],
                # )
                # email.fail_silently = True
                # email.send()


                return redirect('create_profile')

        elif password != password2:
            messages.info(request, 'Password is incorrect')
            return redirect('signup')

    else: 
        return render(request, 'signup.html')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('create_profile')


def signin(request):
    user = request.user
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)

        if user is None:
            return redirect('signin')
        
        else:
            login(request, user)
            return redirect ('profile', user.id )
    
    else:
        return render(request, 'homepage.html', {'form': AuthenticationForm})


def signout(request):
    if request.user.is_authenticated:
        logout(request)
    
    return redirect('signin')


@login_required(login_url='signin')
def profile(request, pk):

    user = User.objects.get(id=pk)
    user_profile = UserProfile.objects.get(user=user)
    current_user = request.user
    current_user_profile = current_user.userprofile
    sent_friend_request = FriendRequest.objects.filter(sender=current_user_profile, receiver=user_profile)
    current_user_friends = current_user_profile.friends.all()
    user_friends = user_profile.friends.all()

    context = {'user': user, 'user_profile': user_profile,
                'current_user':current_user, 'current_user_profile':current_user_profile,
                'sent_friend_request': sent_friend_request, 'current_user_friends': current_user_friends,
                'user_friends':user_friends}
    return render(request, 'profile/profile.html', context)


@login_required(login_url='signin')
def create_profile(request):
    current_user = request.user
    current_user_profile = current_user.userprofile
    form = ProfileForm(instance=current_user_profile)
    context = {'current_user_profile': current_user_profile, 'form': form, 'current_user': current_user}
    if request.method == 'POST':

        form = ProfileForm(request.POST, instance=current_user_profile)

        if form.is_valid():
        
            form.save()

            if request.FILES.get('image') == None:
                image = current_user_profile.image
                hobbies = request.POST['hobbies']
                location = request.POST['location']

                current_user_profile.image = image
                current_user_profile.hobbies = hobbies
                current_user_profile.location = location
                current_user_profile.save()

            if request.FILES.get('image') != None:
                image = request.FILES.get('image')
                hobbies = request.POST['hobbies']
                location = request.POST['location']

                current_user_profile.image = image
                current_user_profile.hobbies = hobbies
                current_user_profile.location = location
                current_user_profile.save()
        
        return redirect('profile', current_user.id)

    return render(request, 'create_profile.html', context)

    

def chats(request, pk):
    current_user = request.user
    user = request.user.userprofile
    friends = user.friends.all()
    friend = get_object_or_404(UserProfile, pk=pk)
    last_msg = Chat.objects.last()
    form = ChatForm()
    current_user_profile = request.user.userprofile
    profile = UserProfile.objects.get(id = friend.id)
    chats = Chat.objects.all()
    received_chats = Chat.objects.filter(sender=profile, receiver=current_user_profile, message_seen = False)

    # if 'q' in request.GET:
    #     q = request.GET['q']
    #     friends = UserProfile.objects.filter(friends__icontains = q)
    # else:
    #     friends = user.friends.all()
    context = {'friends': friends, 'user': user, 'last_msg':last_msg, 'current_user': current_user, 'friend':friend,
                'form': form, 'current_user_profile': current_user_profile, 'profile': profile,  
                'chats': chats, 'num': received_chats.count()}

    return render(request, 'profile/chats.html', context)


def chat(request, pk):
    current_user = request.user
    friend = get_object_or_404(UserProfile, pk=pk)
    current_user_profile = request.user.userprofile
    profile = UserProfile.objects.get(id = friend.id)
    received_chats = Chat.objects.filter(sender=profile, receiver=current_user_profile, message_seen = False)
    received_chats.update(message_seen=True)
    chats = Chat.objects.filter(sender=profile, receiver=current_user_profile)
    msgs = []
    for chat in chats:
        res = {'sender': chat.sender.name,
            'sender_id': chat.sender.id,
            'receiver': chat.receiver.name,
            'reveiver_id': chat.receiver.id,
            'message': chat.body,
            'msg_id': chat.id,
        }
        msgs.append(res)

    chats = Chat.objects.filter(sender=current_user_profile, receiver=profile)
    for chat in chats:
        res = {'sender': chat.sender.name,
            'sender_id': chat.sender.id,
            'receiver': chat.receiver.name,
            'reveiver_id': chat.receiver.id,
            'message': chat.body,
            'msg_id': chat.id
        }
        msgs.append(res)
    
    msgs = sorted(msgs, key=lambda x: (x['msg_id']))
    
    return JsonResponse(msgs, safe=False )



def sentMessage(request, pk):
    user = request.user.userprofile
    friend = get_object_or_404(UserProfile, pk=pk)
    profile = UserProfile.objects.get(id=friend.id)
    new_message = Chat.objects.create(sender = user,
                                    receiver = profile, message_seen = False)

    return JsonResponse(new_message.body, safe=False )


def receivedMessage(request, pk):
    user = request.user.userprofile
    friend = get_object_or_404(UserProfile, pk=pk)
    profile = UserProfile.objects.get(id=friend.id)
    messages = Chat.objects.filter(sender=profile, receiver=user)
    arr = []

    for message in messages:
        arr.append(message.body)

    return JsonResponse(arr, safe=False)


def not_seen(request, pk):
    user = request.user.userprofile
    friend = get_object_or_404(UserProfile, pk=pk)
    profile = UserProfile.objects.get(id=friend.id)
    messages = Chat.objects.filter(sender=profile, receiver=user, message_seen=False)

    message_list = [{
        "sender_id": message.sender.id,
        "message": message.body,

    } for message in messages]

    messages.update(message_seen=True)
    
    return JsonResponse(message_list, safe=False)


def delete_message(request, pk):
   
    message = Chat.objects.get(id=pk)

    message.delete()

    return JsonResponse(pk , safe=False)


def send_message(request, pk):
    user_profile = request.user.userprofile
    friend = get_object_or_404(UserProfile, pk=pk)
    friend_profile = UserProfile.objects.get(id=friend.id)
    data = json.loads(request.body)
    new_message = data["msg"]
    new_chat_message = Chat.objects.create(body=new_message, sender=user_profile, receiver=friend_profile, message_seen=False)


    return JsonResponse(new_chat_message.body, safe=False)
        

def get_last_message(request, pk):
    user = request.user.userprofile
    friend = get_object_or_404(UserProfile, pk=pk)
    current_user_profile = request.user.userprofile
    profile = UserProfile.objects.get(id = friend.id)
    received_chats = Chat.objects.filter(sender=profile, receiver=current_user_profile)
    sended_chats = Chat.objects.filter(sender=current_user_profile, receiver=profile)

    msgs = []
    for chat in received_chats:
        res = {'sender': chat.sender.name,
            'sender_id': chat.sender.id,
            'receiver': chat.receiver.name,
            'reveiver_id': chat.receiver.id,
            'message': chat.body,
            'msg_id': chat.id,
        }
        msgs.append(res)

    chats = Chat.objects.filter(sender=current_user_profile, receiver=profile)
    for chat in sended_chats:
        res = {'sender': chat.sender.name,
            'sender_id': chat.sender.id,
            'receiver': chat.receiver.name,
            'reveiver_id': chat.receiver.id,
            'message': chat.body,
            'msg_id': chat.id,
        }
        msgs.append(res)


    msgs = sorted(msgs, key=lambda x: (x['msg_id']))

    return JsonResponse(msgs[-1], safe=False)



     


def friends(request, pk):

    current_user = request.user
    current_user_profile = current_user.userprofile
    current_user_friends = current_user_profile.friends.all()
    friend_request_sender = FriendRequest.sender


    user = get_object_or_404(User, pk=pk)
    user_profile = UserProfile.objects.get(user = user)
    friends = user_profile.friends.all()

    users = User.objects.all()

    sent_friend_requests = FriendRequest.objects.filter(sender=current_user.userprofile)
    rec_friend_requests = FriendRequest.objects.filter(receiver=current_user.userprofile)

    context = {'user':user, 'current_user':current_user, 'friends':friends, 
                'users':users, 'sent_friend_requests': sent_friend_requests,
                'rec_friend_requests': rec_friend_requests, 'user_profile': user_profile,
                 'current_user_friends': current_user_friends, 'friend_request_sender': friend_request_sender}

    return render(request, 'profile/friends.html', context)


def send_friend_request(request, pk):

    sender = request.user
    sender_pr = sender.userprofile
    receiver = User.objects.get(id=pk)
    receiver_pr = receiver.userprofile

    if isFriendRequestExists(receiver_pr, sender_pr):
        try:
            accept_friend_request(request, pk)
            created = True
        except:
            created = False
    else:
        friend_request, created = FriendRequest.objects.get_or_create(sender=sender_pr,receiver=receiver_pr)
    
    if created:
        return redirect('profile', pk=pk)
    else:
        return redirect('profile', pk=pk)


def isFriendRequestExists(sender, receiver):
    print('checking...')
    try:
        friend_request = FriendRequest.objects.get(sender=sender, receiver=receiver)
        friend_request.receiver.friends.add(friend_request.sender)
        friend_request.sender.friends.add(friend_request.receiver)
        friend_request.delete()
        return True
    except Exception as e:
        print(e)
    return False


def delete_friend_request(request, pk):

    sender = request.user
    receiver = User.objects.get(id=pk)
    sender_pr = sender.userprofile
    receiver_pr = receiver.userprofile

    friend_request = FriendRequest.objects.get(sender=sender_pr,receiver=receiver_pr)

    if friend_request.sender == sender_pr:

        friend_request.delete()
        messages.success(request, 'Friend request deleted')

        return redirect('profile', pk=pk)
    
    return redirect('profile', pk=pk)



def accept_friend_request(request, pk):

    friend_request = FriendRequest.objects.get(pk=pk)
    receiver_id = friend_request.receiver.id

    if friend_request.receiver == request.user.userprofile:
        friend_request.receiver.friends.add(friend_request.sender)
        friend_request.sender.friends.add(friend_request.receiver)

        friend_request.delete()
        
        return redirect ('friends', pk=receiver_id)




def decline_friend_request(request, pk):

    receiver = request.user.userprofile
    friend_request = FriendRequest.objects.get(pk=pk)

    receiver_id = friend_request.receiver.id

    if friend_request.receiver == receiver:
        friend_request.delete()

        return redirect ('friends', pk=receiver_id)

    
    else:
        accept_friend_request()


def delete_friend(request, pk):

    user = request.user.userprofile
    user2 = User.objects.get(id=pk)
    friend = user2.userprofile

    user.friends.remove(friend)
    friend.friends.remove(user)

    return redirect ('friends', pk=pk)


def notifications(request):
    current_user = request.user
    current_user_profile = current_user.userprofile
    current_user_friends = current_user_profile.friends.all()

    rec_friend_requests = FriendRequest.objects.filter(receiver=current_user_profile)
    messages = Chat.objects.filter(receiver=current_user_profile, message_seen=False)

    friend_request_sender = FriendRequest.sender
    message_request_sender = Chat.sender

    last_msg = Chat.objects.last()

    context = {'current_user': current_user, 'current_user_profile': current_user_profile, 'current_user_friends': current_user_friends,
                'rec_friend_requests': rec_friend_requests, 'messages': messages, 'friend_request_sender': friend_request_sender,
                'message_request_sender': message_request_sender, 'last_msg': last_msg}

    return render(request, 'profile/notifications.html', context)
    

def chatNotification(request):
    current_user_profile = request.user.userprofile
    friends = current_user_profile.friends.all()
    arr = []

    for friend in friends:
        chats = Chat.objects.filter(sender__id=friend.id, receiver=current_user_profile, message_seen=False)
        arr.append(chats.count())

    return JsonResponse(arr, safe=False)


def friendNotifications(request):
    current_user_profile = request.user.userprofile
    friends = current_user_profile.friends.all()
    arr = []

    for friend in friends:
        requests = FriendRequest.objects.filter(sender__id=friend.id, receiver=current_user_profile)
        arr.append(requests.count())

    return JsonResponse(arr, safe=False)

# def signup_redirect(request):
#     messages.error(request, 'Something wrong here')
#     return redirect('signup')