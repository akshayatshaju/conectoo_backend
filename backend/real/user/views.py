from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegisterSerializer,UserLoginSerializer,GetUserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import permissions,generics
from rest_framework.authentication import authenticate
from django.contrib.auth import authenticate
from .models import Account
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.parsers import MultiPartParser
from rest_framework.decorators import api_view, permission_classes
from .serializers import *
from django.db.models import Count,Q
#from django.db.models.functions import ExtractMonth, ExtractYear
#from django.utils import timezone
from posts.serializer import AccountSerializer, GetPostSerializer
from posts.models import Post
from user import helper
from .email import *
from django.core.mail import send_mail
from django.conf import settings

# Assuming you have a DEFAULT_FROM_EMAIL setting in your Django settings
from_email = settings.DEFAULT_FROM_EMAIL





#User Register view

# class UserRegisterView(APIView):
#     def post(self, request):
#         serializer = UserRegisterSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             print(serializer.data,"serializer data")
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         print(serializer.errors)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
   
from django.conf import settings

from_email = settings.DEFAULT_FROM_EMAIL

class UserRegisterView(APIView):
    print("enter to register view")
    def post(self, request, format=None):
        # Generate OTP
        otp = ''.join(random.choices('0123456789', k=4))
        print(otp,"otp got to mail")

        # Add OTP and is_active to request data
        copy = request.data.copy()
        print(copy, "copy of otp")
        copy['otp'] = otp
        copy['is_active'] = False

        # Create serializer instance with modified data
        serializer = UserRegisterSerializer(data=copy)
        print("seriliazer instance is modified")

        if serializer.is_valid():
            user = serializer.save()
            print(user,"user is identified")
            # Ensure OTP is associated with the user
            user.otp = otp
            print("otp is associated with the user")
            user.save()
            # Send OTP via email
            send_otp_via_email(user.email, otp, from_email)
            print("otp is send via email")
            return Response({'msg': "Registration successful. OTP sent to your email."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
def send_otp_via_email(email, otp, from_email):
 
    # Define recipient's email address
    recipient_list = [email]
    
    # Define email subject and message
    subject = 'Your OTP for registration'
    message = f'Your OTP for Connectoo social media registration is: {otp}'
   
    
    # Send email
    send_mail(subject, message, from_email, recipient_list)

#-----------------------------email veification--------------------------------    
class VerifyEmail(APIView):
    permission_classes = [AllowAny]
    

    def post(self, request):
        print("entered into verifiemal")
        
        try:
            data = request.data
            print("data:", data)
            
            email = data.get('email', '')
            print("email:", email)
            
            otp = data.get('otp', '')
            print("otp:", otp)
            

            if not email or not otp:
                return Response({"message": "Email and OTP are required fields"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = Account.objects.get(email=email)
                print(user, "user")
            except Account.DoesNotExist:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            if user.otp == otp:
                
                print("User's OTP:", user.otp)
                
                user.is_active = True
                print("user is active")
                
                user.save()
                print("user is saved")
                
                return Response({"message": "Account Verified"}, status=status.HTTP_200_OK)
            else:
                print("Entered OTP:", otp)
                print("User's OTP:", user.otp)
                user.is_active = False
                user.save()
                print(user, "user is saved")
                return Response({"message": "Wrong OTP"}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"message": f"Something went wrong: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    




class EmailVerificationFailed(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        try:
            data = request.data
            email = data['email']
            print(email, "email from emailverificationfailed")
            user = Account.objects.get(email = email)
            if user :
                user.delete()
                return Response({"message":"User poped out of table"},status=status.HTTP_200_OK)
            return Response({"message":"User not in table"},status=status.HTTP_200_OK)
        except:
            return Response({"message":"No got got from verify otp page"},status=status.HTTP_404_NOT_FOUND)
        
        
   
#------------Login---------------------------------------


    
class UserLoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email_or_username = serializer.validated_data.get('email_or_username')
            password = serializer.validated_data.get('password')
            print(email_or_username, password)
            # Authenticate user
            
            try:
                # authenticate with email or username
                user = authenticate(request, username=email_or_username, password=password)
                print(user)
                
                # if user instance is returned and create token and considered as user logged in
                if user:
                    if user.is_deleted:
                        return Response({"details": "This account has been deleted."}, status=401)

                    print("success login")
                    refresh = RefreshToken.for_user(user)
                    refresh['email'] = user.email
                    refresh['is_superuser'] = user.is_superuser
                    access_token = str(refresh.access_token)
                    refresh_token = str(refresh)

                    return Response(
                        {
                            "email_or_username": email_or_username,
                            "password": password,
                            "access": access_token,
                            "refresh": refresh_token,
                        },
                        status=201,
                    )
                else:
                    # If user is None, wrong email or password
                    return Response({"details": "Invalid email or password"}, status=401)

            except Account.DoesNotExist:
                # If user doesn't exist, wrong email or password
                return Response({"details": "no user email or password"}, status=401)


#--------------google authentication----------------------
from google.auth.transport.requests import Request as AuthRequest
from google.oauth2 import id_token

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        token = request.data['google_token']
        print(token, "token is getting")
        
        if not token:
            return Response({"error": "Google token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            print("ssss")
            
            auth_request = AuthRequest()
            print(auth_request,"auth_request")

            # Validate the Google OAuth token
            id_info = id_token.verify_oauth2_token(token, auth_request)
            print(id_info,"id_info")

            user_email = id_info['email']
         

            print(user_email, "useremailll")
            
            try:
                print("try")
                user_exist = Account.objects.get(email=user_email)
                if user_exist.is_deleted:
                        return Response({"details": "This account has been deleted."}, status=401)

                print("success login")
                refresh = RefreshToken.for_user(user_exist)
                refresh['email'] = user_exist.email
                refresh['is_superuser'] = user_exist.is_superuser
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                return Response(
                    {
                        "email_or_username": user_email,
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                    status=201,
                )
            except Account.DoesNotExist:
                print("except")
                return Response({"details": "User does not exist."}, status=status.HTTP_401_UNAUTHORIZED)

        except ValueError as e:
            return Response({'error': f'Invalid token: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)













#-----------------------------------------------------------------------------------------------------------------------------       
    
    
# get details of logged in user
class GetUserView(APIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=[JWTAuthentication]
 
    def get(self,request):
    
        user_email = request.user
        print(request.user)
        user_details = Account.objects.get(email=user_email)
        serializer = GetUserSerializer(instance=user_details)
        print(serializer.data)
        return Response(serializer.data,status=200)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def CheckAuth(request):
    # If the view reaches here, the user is authenticated
    return Response({'message': 'Authenticated'})


from django.conf import settings

class ChangeProfilePicView(APIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=[JWTAuthentication]
    parser_classes = [MultiPartParser]
    def patch(self,request):
        print(request.data)
        u = request.user
        print(request.data.get('profile_pic'))
        u.profile_pic = request.data.get('profile_pic')
        u.save()
        print(u.profile_pic)
        full_path = f"{settings.CUSTOM_DOMAIN}{settings.MEDIA_URL}{u.profile_pic}"
        print(full_path)
        return Response({'message':"success",'updatedProfilePic':full_path},status=200)
    
    
class EditProfileView(APIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=[JWTAuthentication]
    
    def patch(self,request):
        print(request.data)
        u = request.user
        u.username = request.data.get('username')
        u.first_name = request.data.get('first_name')
        u.email = request.data.get('email')
        u.phone = request.data.get('phone')
        u.save()
        return Response({'message':"success"},status=200)
    
    
class ChangePassword(APIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=[JWTAuthentication]
    
    def patch(self,request):
        print(request.data)
        u = request.user
        if u:
            password = request.data['password']
            print(u.password," before changing")
            u.password = make_password(password)
            u.save()
            print(u.password," after changing")
            
            return Response({'message':"success"},status=200)
        else:
            return Response({'message':"fail"},status=status.HTTP_400_BAD_REQUEST)
        
        
class CustomUserSearchAPIView(APIView):
    def get(self, request, *args, **kwargs):
        query = request.query_params.get('query', None)

        if not query:
            return Response({'error': 'Query parameter "query" is required'}, status=status.HTTP_400_BAD_REQUEST)

        queryset = Account.objects.filter(Q(username__icontains=query)|Q(email__icontains=query)).exclude(pk=request.user.id)
        print(queryset)
        


        serializer = GetUserSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class GetOtherUserView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = Account.objects.all()
    serializer_class = AccountSerializer
    lookup_field = 'id'

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance,context={'request':request})
       
        post_serializer = GetPostSerializer( Post.objects.filter(user=instance)
        , many=True,context={'request':request})

        return Response({'posts': post_serializer.data,'user_data': serializer.data})
    
    
    

                

       
      

            
            
            



    