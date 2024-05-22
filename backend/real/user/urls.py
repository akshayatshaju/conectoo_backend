from django.urls import path
from .views import*
from rest_framework_simplejwt.views import TokenRefreshView 

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    # path('registerrr/', UserRegisterViewe.as_view(), name='registerrr'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('user',GetUserView.as_view(),name='user'),
    path('check-auth/', CheckAuth, name='check-auth'),
    path('refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('search/', CustomUserSearchAPIView.as_view(), name='search'),
    path('getusers/<int:id>/', GetOtherUserView.as_view(), name='get_user'),
    
    
    path('changeprofile',ChangeProfilePicView.as_view(),name='changeprofile'),
    path('editprofile',EditProfileView.as_view(),name='editprofile'),
    
   
    
    path('verifyemail/',VerifyEmail.as_view(),name='verifyemail'),
    path('verify-failed/',EmailVerificationFailed.as_view(),name='verify-failed'),
    
    path('googlelogin/',GoogleLoginView.as_view(),name='googlelogin'),
   
  
]